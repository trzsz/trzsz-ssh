/*
MIT License

Copyright (c) 2023-2026 The Trzsz SSH Authors.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package tssh

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// kMuxAllTokens is the full ControlPath token set (OpenSSH >= 9.6 also supports %j).
const kMuxAllTokens = "%CdhijkLlnpru"

// resolveControlPathOption returns the configured ControlPath, or "" if multiplexing is disabled.
func resolveControlPathOption(args *sshArgs) string {
	ctrlPath := args.ControlPath
	if ctrlPath == "" {
		ctrlPath = getOptionConfig(args, "ControlPath")
	}
	if strings.EqualFold(ctrlPath, "none") {
		return ""
	}
	return ctrlPath
}

// getControlMasterMode reports whether this process should become a master (yes/-M) or
// should become one only if no master is running yet (auto).
func getControlMasterMode(args *sshArgs) (master, auto bool) {
	if args.ControlMaster {
		return true, false
	}
	switch strings.ToLower(getOptionConfig(args, "ControlMaster")) {
	case "yes", "ask", "true":
		return true, false
	case "auto", "autoask":
		return false, true
	}
	return false, false
}

// resolveControlSocket expands the ControlPath of dest for a control command.
func resolveControlSocket(args *sshArgs, dest string) (string, error) {
	args.Destination = dest
	args.originalDest = dest
	ctrlPath := resolveControlPathOption(args)
	if ctrlPath == "" {
		return "", fmt.Errorf("no ControlPath specified for [%s]", dest)
	}
	param, err := getSshParam(args, false)
	if err != nil {
		return "", err
	}
	socket, err := expandTokens(ctrlPath, param, kMuxAllTokens)
	if err != nil {
		return "", fmt.Errorf("expand ControlPath [%s] failed: %v", ctrlPath, err)
	}
	return resolveHomeDir(socket), nil
}

// muxClientHello performs the client side of the mux HELLO exchange.
func muxClientHello(rw io.ReadWriter) error {
	if err := muxWriteMessage(rw, kMuxMsgHello, kMuxProtocolVersion); err != nil {
		return fmt.Errorf("write mux hello failed: %v", err)
	}
	msgType, body, err := muxReadMessage(rw)
	if err != nil {
		return fmt.Errorf("read mux hello failed: %v", err)
	}
	if msgType != kMuxMsgHello {
		return fmt.Errorf("expected mux hello, got 0x%08x", msgType)
	}
	version, ok := muxReadUint32(&body)
	if !ok {
		return fmt.Errorf("mux hello missing protocol version")
	}
	if version != kMuxProtocolVersion {
		return fmt.Errorf("unsupported mux protocol version %d", version)
	}
	return nil
}

// muxControlCommand sends `check`, `exit` or `stop` to the master listening on socket.
// It speaks the OpenSSH mux protocol, so it works with both tssh and OpenSSH masters.
func muxControlCommand(socket, ctlCmd string) int {
	conn, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Control socket connect(%s): %v\r\n", socket, err)
		return kExitCodeToolsError
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(kMuxHandshakeTimeout))

	if err := muxClientHello(conn); err != nil {
		fmt.Fprintf(os.Stderr, "Control socket %s: %v\r\n", socket, err)
		return kExitCodeToolsError
	}

	const rid uint32 = 1
	var request, expect uint32
	var okMessage string
	switch strings.ToLower(ctlCmd) {
	case "check":
		request, expect = kMuxCAliveCheck, kMuxSAlive
	case "exit":
		request, expect, okMessage = kMuxCTerminate, kMuxSOk, "Exit request sent."
	case "stop":
		request, expect, okMessage = kMuxCStopListening, kMuxSOk, "Stop listening request sent."
	default:
		fmt.Fprintf(os.Stderr, "Invalid multiplex command: %s\r\n", ctlCmd)
		return kExitCodeToolsError
	}

	if err := muxWriteMessage(conn, request, rid); err != nil {
		fmt.Fprintf(os.Stderr, "Control socket %s: write failed: %v\r\n", socket, err)
		return kExitCodeToolsError
	}
	msgType, body, err := muxReadMessage(conn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Control socket %s: read failed: %v\r\n", socket, err)
		return kExitCodeToolsError
	}
	if gotRid, ok := muxReadUint32(&body); !ok || gotRid != rid {
		fmt.Fprintf(os.Stderr, "Control socket %s: unexpected request id in reply\r\n", socket)
		return kExitCodeToolsError
	}
	switch msgType {
	case expect:
		if msgType == kMuxSAlive {
			pid, _ := muxReadUint32(&body)
			fmt.Fprintf(os.Stderr, "Master running (pid=%d)\r\n", pid)
		} else {
			fmt.Fprintf(os.Stderr, "%s\r\n", okMessage)
		}
		return 0
	case kMuxSPermissionDenied, kMuxSFailure:
		reason, _ := muxReadString(&body)
		fmt.Fprintf(os.Stderr, "Control request failed: %s\r\n", reason)
		return kExitCodeToolsError
	default:
		fmt.Fprintf(os.Stderr, "Control socket %s: unexpected reply 0x%08x\r\n", socket, msgType)
		return kExitCodeToolsError
	}
}

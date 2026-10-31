//go:build !windows

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
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"
)

// resolveControlPath returns the configured ControlPath, or "" if multiplexing is disabled.
func resolveControlPath(param *sshParam) string {
	ctrlPath := param.args.ControlPath
	if ctrlPath == "" {
		ctrlPath = getOptionConfig(param.args, "ControlPath")
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

// resolveControlSocket expands the ControlPath tokens for the given SSH parameters.
func resolveControlSocket(param *sshParam, ctrlPath string) (string, error) {
	socket, err := expandTokens(ctrlPath, param, "%CdhijkLlnpru")
	if err != nil {
		return "", fmt.Errorf("expand ControlPath [%s] failed: %v", ctrlPath, err)
	}
	return resolveHomeDir(socket), nil
}

// isMuxConnClosed reports whether err means the master closed the control connection.
func isMuxConnClosed(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE)
}

// muxControlCommand sends `check`, `exit` or `stop` to the master listening on socket.
// It speaks the OpenSSH mux protocol, so it works with both tssh and OpenSSH masters.
func muxControlCommand(socket, ctlCmd string) int {
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

	client, err := dialMuxMaster(socket, time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Control socket connect(%s): %v\r\n", socket, err)
		return kExitCodeToolsError
	}
	defer client.close()
	_ = client.conn.SetDeadline(time.Now().Add(kMuxHandshakeTimeout))

	replyType, body, err := client.request(request)
	if err != nil && request == kMuxCTerminate && isMuxConnClosed(err) {
		// like OpenSSH: the master may exit before its reply is read
		replyType, err = kMuxSOk, nil
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Control socket %s: %v\r\n", socket, err)
		return kExitCodeToolsError
	}
	if replyType != expect {
		fmt.Fprintf(os.Stderr, "Control request failed: %v\r\n", muxReplyError(replyType, body))
		return kExitCodeToolsError
	}
	if replyType == kMuxSAlive {
		pid, _ := muxReadUint32(&body)
		fmt.Fprintf(os.Stderr, "Master running (pid=%d)\r\n", pid)
	} else {
		fmt.Fprintf(os.Stderr, "%s\r\n", okMessage)
	}
	return 0
}

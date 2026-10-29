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
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const kOpenSSH = "ssh"

// execControlCmd handles a multiplexing control command (`tssh -O <ctl_cmd>`).
// The commands use the mux protocol and work with tssh and OpenSSH masters; only `proxy`
// is passed to OpenSSH and its exit code propagated.
func execControlCmd(args *sshArgs, dest string) int {
	switch ctlCmd := strings.ToLower(args.ControlCmd); ctlCmd {
	case "check", "exit", "stop", "forward", "cancel":
		args.Destination = dest
		param, err := getSshParam(args, false)
		if err != nil {
			warning("parse login param failed: %v", err)
			return kExitCodeToolsError
		}
		ctrlPath := resolveControlPath(param)
		if ctrlPath == "" {
			warning("no ControlPath specified for [%s]", dest)
			return kExitCodeToolsError
		}
		socket, err := resolveControlSocket(param, ctrlPath)
		if err != nil {
			warning("resolve control socket failed: %v", err)
			return kExitCodeToolsError
		}
		if ctlCmd == "forward" || ctlCmd == "cancel" {
			return muxForwardCommand(socket, param, ctlCmd == "cancel")
		}
		return muxControlCommand(socket, ctlCmd)
	}

	cmdArgs, err := replaceOrAppendDest(os.Args[1:], args.Destination, dest)
	if err != nil {
		warning("replace or append destination failed: %v", err)
		return kExitCodeToolsError
	}

	sshPath, _, _, err := getOpenSSH()
	if err != nil {
		warning("can't find openssh program: %v", err)
		return kExitCodeToolsError
	}

	cmd := exec.Command(sshPath, cmdArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if enableDebugLogging {
		debug("control command: %s %s", sshPath, strings.Join(cmdArgs, " "))
	}

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		warning("control command %v failed: %v", cmdArgs, err)
		return kExitCodeToolsError
	}

	return 0
}

var ctrlExpectObsoleteOnce sync.Once

// warnObsoleteCtrlExpect warns once if the host still has the `Ctrl` prefixed expect options.
// They fed the password prompt of the OpenSSH master, which tssh no longer starts.
func warnObsoleteCtrlExpect(args *sshArgs) {
	if getExOptionConfig(args, "CtrlExpectCount") == "" {
		return
	}
	ctrlExpectObsoleteOnce.Do(func() {
		warning("the Ctrl prefixed automated interaction options (CtrlExpectCount, ...) are obsolete and ignored, " +
			"tssh is its own control master now; use the ExpectCount / ExpectPattern options instead")
	})
}

// connectViaControl implements ControlMaster / ControlPath. tssh itself is the control master
// (see startMuxMaster); with ControlPersist the master runs in background (see startMuxPersistMaster).
func connectViaControl(param *sshParam) SshClient {
	ctrlPath := resolveControlPath(param)
	if ctrlPath == "" {
		return nil
	}

	warnObsoleteCtrlExpect(param.args)

	socket, err := resolveControlSocket(param, ctrlPath)
	if err != nil {
		warning("resolve control socket failed: %v", err)
		return nil
	}

	master, auto := getControlMasterMode(param.args)
	if param.muxPersisted {
		// the background master for this login is already listening on the socket
		master, auto = false, false
	}

	if master {
		if isFileExist(socket) {
			warning("control socket [%s] already exists, disabling multiplexing", socket)
			return nil
		}
		param.muxMasterPath = socket
		return nil
	}

	debug("login to [%s] via control path: %s", param.args.Destination, socket)
	conn, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		// In auto mode, fall back to becoming the master if no usable master exists.
		if auto {
			if removeStaleMuxSocket(socket) || !isFileExist(socket) {
				param.muxMasterPath = socket
			} else {
				warning("control socket [%s] is not usable, disabling multiplexing: %v", socket, err)
			}
			return nil
		}
		warning("login to [%s] dial control path [%s] failed: %v", param.args.Destination, socket, err)
		return nil
	}

	ncc, chans, reqs, err := ssh.NewControlClientConn(conn)
	if err != nil {
		_ = conn.Close()
		warning("login to [%s] new conn from control path [%s] failed: %v", param.args.Destination, socket, err)
		return nil
	}

	client := sshNewClient(ncc, chans, reqs)
	debug("login to [%s] via control path [%s] success", param.args.Destination, socket)

	if param.udpMode != kUdpModeNo && isUdpMuxMaster(client) {
		debug("control socket [%s] is a tssh UDP master", socket)
		param.udpTransport = true
	}

	return client
}

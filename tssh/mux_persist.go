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
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// This file implements ControlPersist the way OpenSSH does: the first login starts the
// control master in the background and then runs its own session as a client of it, so
// the master outlives the session that created it.

// kMuxPersistEnv marks the background master process; the result of its login is reported
// to the starting process through the pipe on file descriptor 3.
const kMuxPersistEnv = "TSSH_MUX_PERSIST_MASTER"

const kMuxPersistReady = "ok\n"

// getControlPersist reports whether ControlPersist is enabled and how long the master
// stays alive after the last client disconnected (0 means until it is told to exit).
func getControlPersist(args *sshArgs) (bool, time.Duration) {
	persist := getOptionConfig(args, "ControlPersist")
	switch strings.ToLower(persist) {
	case "", "no", "false":
		return false, 0
	case "yes", "true":
		return true, 0
	}
	seconds, err := convertSshTime(persist)
	if err != nil {
		warning("ControlPersist [%s] is invalid: %v", persist, err)
		return false, 0
	}
	return true, time.Duration(seconds) * time.Second
}

func isMuxPersistMaster() bool {
	return os.Getenv(kMuxPersistEnv) != ""
}

// startMuxPersistMaster starts a background control master for ControlPersist and attaches to
// it. The master logs in on this terminal, so password prompts and host key confirmations work
// as usual. It returns false when no background master is used and the normal login follows.
func startMuxPersistMaster(param *sshParam) (int, bool) {
	args := param.args
	persist, _ := getControlPersist(args)
	if !persist {
		return 0, false
	}
	master, auto := getControlMasterMode(args)
	if !master && !auto {
		return 0, false
	}
	ctrlPath := resolveControlPath(param)
	if ctrlPath == "" {
		return 0, false
	}
	socket, err := resolveControlSocket(param, ctrlPath)
	if err != nil {
		return 0, false
	}
	// an existing socket is either a running master or refused for -M, see connectViaControl
	if isFileExist(socket) && (master || !removeStaleMuxSocket(socket)) {
		return 0, false
	}

	code, err := spawnMuxPersistMaster()
	if err != nil {
		if code != 0 {
			// the background master failed to log in and has reported why
			return code, true
		}
		warning("start control master in background failed: %v", err)
		return 0, false
	}
	debug("control master for [%s] is running in background on [%s]", args.Destination, socket)

	// the background master owns the forwardings of the command line
	param.muxPersisted = true
	if code, ok := runAsMuxPassenger(param); ok {
		return code, true
	}
	// features that need proxy mode connect to the background master in connectViaControl
	return 0, false
}

// spawnMuxPersistMaster runs this program again as the background master and waits for its login.
// On a failed login it returns the exit code of the background process.
func spawnMuxPersistMaster() (int, error) {
	exe, err := os.Executable()
	if err != nil {
		return 0, err
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return 0, err
	}
	defer func() { _ = reader.Close() }()

	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Env = append(os.Environ(), kMuxPersistEnv+"=1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{writer}
	err = cmd.Start()
	_ = writer.Close() // Close the parent's write end to allow EOF.
	if err != nil {
		return 0, err
	}

	result := make(chan string, 1)
	go func() {
		buf, _ := io.ReadAll(reader)
		result <- string(buf)
	}()

	// Ctrl+C reaches the background master as well while it is logging in
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	select {
	case msg := <-result:
		if msg == kMuxPersistReady {
			_ = cmd.Process.Release()
			return 0, nil
		}
	case sig := <-sigCh:
		_ = cmd.Process.Signal(sig)
	}

	err = cmd.Wait()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() > 0 {
		return exitErr.ExitCode(), fmt.Errorf("background control master exited with code %d", exitErr.ExitCode())
	}
	return kExitCodeLoginFailed, fmt.Errorf("background control master exited: %v", err)
}

// runMuxPersistMaster is the main of the background master: it logs in, starts listening on
// the control socket, detaches from the terminal and serves the clients until it may exit.
func runMuxPersistMaster(param *sshParam) (int, error) {
	notify := os.NewFile(3, "mux-persist")
	_ = os.Unsetenv(kMuxPersistEnv)
	if notify == nil {
		return kExitCodeToolsError, fmt.Errorf("control master started without notify pipe")
	}
	defer func() { _ = notify.Close() }()

	args := param.args
	// the starting process made sure the socket is free; the session is run by the clients
	args.ControlMaster = true
	args.NoCommand = true
	_, timeout := getControlPersist(args)

	sshConn, err := sshConnectWithParam(param)
	if err != nil {
		return kExitCodeLoginFailed, err
	}
	defer func() {
		cleanupOnClose()
		sshConn.Close()
	}()

	m := findMuxMaster(param.muxMasterPath)
	if m == nil {
		return kExitCodeLoginFailed, fmt.Errorf("control master is not listening")
	}

	sshPortForward(sshConn)

	if err := detachFromTerminal(); err != nil {
		return kExitCodeToolsError, fmt.Errorf("detach control master from terminal failed: %v", err)
	}
	if _, err := notify.WriteString(kMuxPersistReady); err != nil {
		return kExitCodeToolsError, err
	}
	_ = notify.Close()

	m.persist(sshConn, timeout)
	return 0, nil
}

func findMuxMaster(socket string) *muxMaster {
	muxMastersMu.Lock()
	defer muxMastersMu.Unlock()
	for _, m := range muxMasters {
		if m.socket == socket {
			return m
		}
	}
	return nil
}

// detachFromTerminal starts a new session without controlling terminal and points the
// standard file descriptors to /dev/null, so the master survives the terminal.
func detachFromTerminal() error {
	if _, err := syscall.Setsid(); err != nil {
		return err
	}
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer func() { _ = devNull.Close() }()
	for _, fd := range []int{0, 1, 2} {
		if err := unix.Dup2(int(devNull.Fd()), fd); err != nil {
			return err
		}
	}
	isTerminal = false
	return nil
}

// persist keeps the background master running until the connection is gone, it is told to
// exit, or no client was connected for timeout (0 waits for an exit request).
func (m *muxMaster) persist(sshConn *sshConnection, timeout time.Duration) {
	lost := make(chan struct{})
	go func() {
		_ = sshConn.client.Wait()
		close(lost)
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	var idleSince time.Time
	for {
		select {
		case <-lost:
			debug("control master: connection closed")
			return
		case sig := <-sigCh:
			debug("control master: exit on signal [%v]", sig)
			return
		case now := <-ticker.C:
			if m.closed.Load() {
				return
			}
			if m.clientCount() > 0 {
				idleSince = time.Time{}
				continue
			}
			if !m.listening.Load() {
				debug("control master: stopped listening and the last client left")
				return
			}
			if timeout <= 0 {
				continue
			}
			if idleSince.IsZero() {
				idleSince = now
			} else if now.Sub(idleSince) >= timeout {
				debug("control master: no client for %v, exiting", timeout)
				return
			}
		}
	}
}

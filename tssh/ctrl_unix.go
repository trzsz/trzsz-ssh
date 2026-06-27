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
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

const kOpenSSH = "ssh"

type controlMaster struct {
	path    string
	args    []string
	cmd     *exec.Cmd
	ptmx    *os.File
	stdout  io.ReadCloser
	stderr  io.ReadCloser
	exited  atomic.Bool
	success atomic.Bool
}

func (c *controlMaster) handleStderr() {
	go func() {
		defer func() { _ = c.stderr.Close() }()
		var output []string
		scanner := bufio.NewScanner(c.stderr)
		for scanner.Scan() {
			out := scanner.Text()
			if c.success.Load() {
				continue
			}
			if strings.HasPrefix(out, "debug") {
				fmt.Fprintf(os.Stderr, "%s\r\n", out)
			} else {
				output = append(output, out)
			}
		}
		if !c.success.Load() {
			for _, out := range output {
				warning("%s", out)
			}
		}
	}()
}

func (c *controlMaster) handleStdout() <-chan error {
	doneCh := make(chan error, 1)
	go func() {
		defer func() { _ = c.stdout.Close() }()
		defer close(doneCh)
		buf := make([]byte, 1000)
		for {
			n, err := c.stdout.Read(buf)
			if err != nil || n <= 0 {
				doneCh <- fmt.Errorf("read stdout failed: %v", err)
				return
			}
			out := strings.TrimSpace(ansi.Strip(string(buf[:n])))
			if out == "" {
				continue
			}
			if out == "ok" {
				doneCh <- nil
			} else {
				doneCh <- fmt.Errorf("control master stdout invalid: %v", strconv.QuoteToASCII(string(buf[:n])))
			}
			return
		}
	}()
	return doneCh
}

func (c *controlMaster) fillPassword(param *sshParam, expectCount int) (cancel context.CancelFunc) {
	var ctx context.Context
	expectTimeout := getExpectTimeout(param.args, "Ctrl")
	if expectTimeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), time.Duration(expectTimeout)*time.Second)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}

	expect := &sshExpect{
		param: param,
		ctx:   ctx,
		pre:   "Ctrl",
		out:   make(chan []byte, 100),
	}
	go expect.wrapOutput(c.ptmx, nil, expect.out)
	go func() {
		expect.execInteractions(c.ptmx, expectCount)
		if ctx.Err() == context.DeadlineExceeded {
			warning("expect timeout after %d seconds", expectTimeout)
		}
	}()
	return
}

func (c *controlMaster) checkExit() <-chan struct{} {
	exitCh := make(chan struct{}, 1)
	go func() {
		defer close(exitCh)
		_ = c.cmd.Wait()
		c.exited.Store(true)
		if c.ptmx != nil {
			_ = c.ptmx.Close()
		}
		exitCh <- struct{}{}
	}()
	return exitCh
}

func (c *controlMaster) start(param *sshParam) error {
	var err error
	c.cmd = exec.Command(c.path, c.args...)
	expectCount := getExpectCount(param.args, "Ctrl")
	if expectCount > 0 {
		c.cmd.SysProcAttr = &syscall.SysProcAttr{
			Setsid:  true,
			Setctty: true,
		}
		pty, tty, err := pty.Open()
		if err != nil {
			return fmt.Errorf("open pty failed: %v", err)
		}
		defer func() { _ = tty.Close() }()
		c.cmd.Stdin = tty
		c.ptmx = pty
		cancel := c.fillPassword(param, expectCount)
		defer cancel()
	}
	if c.stdout, err = c.cmd.StdoutPipe(); err != nil {
		return fmt.Errorf("stdout pipe failed: %v", err)
	}
	if c.stderr, err = c.cmd.StderrPipe(); err != nil {
		return fmt.Errorf("stderr pipe failed: %v", err)
	}
	if err := c.cmd.Start(); err != nil {
		return fmt.Errorf("control master start failed: %v", err)
	}

	intCh := make(chan os.Signal, 1)
	signal.Notify(intCh, os.Interrupt)
	defer func() { signal.Stop(intCh); close(intCh) }()

	c.handleStderr()
	exitCh := c.checkExit()
	doneCh := c.handleStdout()

	defer func() {
		if !c.exited.Load() {
			addOnExitFunc(func() { c.quit(exitCh) })
		}
	}()

	for {
		select {
		case err := <-doneCh:
			if err != nil {
				return err
			}
			c.success.Store(true)
			return nil
		case <-exitCh:
			return fmt.Errorf("control master process exited")
		case <-intCh:
			c.quit(exitCh)
			return fmt.Errorf("user interrupt control master")
		}
	}
}

func (c *controlMaster) quit(exitCh <-chan struct{}) {
	if c.exited.Load() {
		return
	}
	_ = c.cmd.Process.Signal(syscall.SIGINT)
	timer := time.AfterFunc(500*time.Millisecond, func() {
		_ = c.cmd.Process.Kill()
	})
	select {
	case <-time.After(time.Second):
	case <-exitCh:
	}
	timer.Stop()
}

func startControlMaster(param *sshParam, sshPath string) error {
	cmdArgs := []string{"-T", "-oRemoteCommand=none",
		"-oConnectTimeout=" + strconv.Itoa(int(getConnectTimeout(param.args)/time.Second))}

	args := param.args
	if args.Debug {
		cmdArgs = append(cmdArgs, "-v")
	}
	if args.IPv4Only {
		cmdArgs = append(cmdArgs, "-4")
	}
	if args.IPv6Only {
		cmdArgs = append(cmdArgs, "-6")
	}
	if args.Gateway {
		cmdArgs = append(cmdArgs, "-g")
	}

	if args.NoForwardAgent {
		cmdArgs = append(cmdArgs, "-a")
	} else if args.ForwardAgent {
		cmdArgs = append(cmdArgs, "-A")
	}
	if args.NoX11Forward {
		cmdArgs = append(cmdArgs, "-x")
	} else {
		if args.X11Forward {
			cmdArgs = append(cmdArgs, "-X")
		}
		if args.X11Trusted {
			cmdArgs = append(cmdArgs, "-Y")
		}
	}

	if args.LoginName != "" {
		cmdArgs = append(cmdArgs, "-l", args.LoginName)
	}
	if args.Port != 0 {
		cmdArgs = append(cmdArgs, "-p", strconv.Itoa(args.Port))
	}
	if args.CipherSpec != "" {
		cmdArgs = append(cmdArgs, "-c", args.CipherSpec)
	}
	if args.ConfigFile != "" {
		cmdArgs = append(cmdArgs, "-F", args.ConfigFile)
	}
	if args.ProxyJump != "" {
		cmdArgs = append(cmdArgs, "-J", args.ProxyJump)
	}
	if args.ControlPath != "" {
		cmdArgs = append(cmdArgs, "-S", args.ControlPath)
	}

	for _, identity := range args.Identity.values {
		cmdArgs = append(cmdArgs, "-i", identity)
	}
	for _, b := range args.DynamicForward.binds {
		cmdArgs = append(cmdArgs, "-D", b.argument)
	}
	for _, f := range args.LocalForward.cfgs {
		cmdArgs = append(cmdArgs, "-L", f.argument)
	}
	for _, f := range args.RemoteForward.cfgs {
		cmdArgs = append(cmdArgs, "-R", f.argument)
	}

	for key, values := range args.Option.options {
		switch key {
		case "remotecommand":
			continue
		default:
			for _, value := range values {
				cmdArgs = append(cmdArgs, fmt.Sprintf("-o%s=%s", key, value))
			}
		}
	}

	if args.originalDest != "" {
		cmdArgs = append(cmdArgs, args.originalDest)
	} else {
		cmdArgs = append(cmdArgs, args.Destination)
	}
	// 10 seconds is enough for tssh to connect
	cmdArgs = append(cmdArgs, "echo ok; sleep 10")

	if enableDebugLogging {
		debug("control master: %s %s", sshPath, strings.Join(cmdArgs, " "))
	}

	ctrlMaster := &controlMaster{path: sshPath, args: cmdArgs}
	if err := ctrlMaster.start(param); err != nil {
		return err
	}
	debug("start control master success")
	return nil
}

// resolveControlSocket resolves the native ssh program and the control socket
// path the same way connectViaControl does: read ControlPath from args or the
// effective config, then expand the version-gated token set and the home directory.
func resolveControlSocket(param *sshParam) (sshPath, socket string, err error) {
	args := param.args
	ctrlPath := args.ControlPath
	if ctrlPath == "" {
		ctrlPath = getOptionConfig(args, "ControlPath")
	}
	switch strings.ToLower(ctrlPath) {
	case "", "none":
		return "", "", fmt.Errorf("no ControlPath configured")
	}

	sshPath, majorVersion, minorVersion, err := getOpenSSH()
	if err != nil {
		return "", "", fmt.Errorf("can't find openssh program: %v", err)
	}
	if majorVersion < 0 || minorVersion < 0 {
		return "", "", fmt.Errorf("can't get openssh version of %s", sshPath)
	}

	tokens := "%CdhijkLlnpru"
	if majorVersion < 9 || (majorVersion == 9 && minorVersion < 6) {
		tokens = "%CdhikLlnpru"
	}
	socket, err = expandTokens(ctrlPath, param, tokens)
	if err != nil {
		return "", "", fmt.Errorf("expand ControlPath [%s] failed: %v", ctrlPath, err)
	}
	return sshPath, resolveHomeDir(socket), nil
}

// execControlCmd forwards an OpenSSH multiplexing control command
// (`tssh -O <ctl_cmd> <destination>`) to the native ssh master process
// listening on the resolved ControlPath socket, and propagates its exit code.
func execControlCmd(args *sshArgs) (int, bool) {
	ctlCmd := strings.ToLower(strings.TrimSpace(args.ControlCmd))
	if !validControlCommands[ctlCmd] {
		warning("unsupported control command [%s], expected one of: check, forward, cancel, exit, stop, proxy", args.ControlCmd)
		return kExitCodeArgsInvalid, true
	}

	if args.Destination == "" {
		warning("a destination is required to control the multiplexing master process")
		return kExitCodeNoDestHost, true
	}

	param, err := getSshParam(args, false)
	if err != nil {
		warning("get ssh param failed: %v", err)
		return kExitCodeArgsInvalid, true
	}

	sshPath, socket, err := resolveControlSocket(param)
	if err != nil {
		warning("can't control the multiplexing master process: %v", err)
		return kExitCodeArgsInvalid, true
	}

	cmdArgs := []string{"-O", ctlCmd, "-S", socket}
	// `forward` and `cancel` act on specific forwarding specs, so pass the
	// requested forwarding arguments and the options that shape them through
	// to the native ssh master (mirroring startControlMaster).
	if ctlCmd == "forward" || ctlCmd == "cancel" {
		if args.Gateway {
			cmdArgs = append(cmdArgs, "-g")
		}
		if args.ConfigFile != "" {
			cmdArgs = append(cmdArgs, "-F", args.ConfigFile)
		}
		for key, values := range args.Option.options {
			if key == "remotecommand" {
				continue
			}
			for _, value := range values {
				cmdArgs = append(cmdArgs, fmt.Sprintf("-o%s=%s", key, value))
			}
		}
		for _, b := range args.DynamicForward.binds {
			cmdArgs = append(cmdArgs, "-D", b.argument)
		}
		for _, f := range args.LocalForward.cfgs {
			cmdArgs = append(cmdArgs, "-L", f.argument)
		}
		for _, f := range args.RemoteForward.cfgs {
			cmdArgs = append(cmdArgs, "-R", f.argument)
		}
	}
	cmdArgs = append(cmdArgs, args.Destination)

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
			return exitErr.ExitCode(), true
		}
		warning("control command [%s] failed: %v", ctlCmd, err)
		return kExitCodeToolsError, true
	}
	return 0, true
}

func connectViaControl(param *sshParam) SshClient {
	args := param.args
	ctrlPath := args.ControlPath
	if ctrlPath == "" {
		ctrlPath = getOptionConfig(args, "ControlPath")
	}

	switch strings.ToLower(ctrlPath) {
	case "", "none":
		return nil
	}

	sshPath, majorVersion, minorVersion, err := getOpenSSH()
	if err != nil {
		warning("can't find openssh program: %v", err)
		return nil
	}
	if majorVersion < 0 || minorVersion < 0 {
		warning("can't get openssh version of %s", sshPath)
		return nil
	}

	tokens := "%CdhijkLlnpru"
	if majorVersion < 9 || (majorVersion == 9 && minorVersion < 6) {
		tokens = "%CdhikLlnpru"
	}
	socket, err := expandTokens(ctrlPath, param, tokens)
	if err != nil {
		warning("expand ControlPath [%s] failed: %v", ctrlPath, err)
		return nil
	}
	socket = resolveHomeDir(socket)

	ctrlMaster := getOptionConfig(args, "ControlMaster")
	switch strings.ToLower(ctrlMaster) {
	case "yes", "ask", "true":
		if isFileExist(socket) {
			warning("control socket [%s] already exists, disabling multiplexing", socket)
			return nil
		}
		fallthrough
	case "auto", "autoask":
		if err := startControlMaster(param, sshPath); err != nil {
			warning("start control master failed: %v", err)
		}
	}

	debug("login to [%s] via control path: %s", args.Destination, socket)

	conn, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		warning("login to [%s] dial control path [%s] failed: %v", args.Destination, socket, err)
		return nil
	}

	ncc, chans, reqs, err := ssh.NewControlClientConn(conn)
	if err != nil {
		warning("login to [%s] new conn from control path [%s] failed: %v", args.Destination, socket, err)
		return nil
	}

	debug("login to [%s] via control path [%s] success", args.Destination, socket)
	return sshNewClient(ncc, chans, reqs)
}

//go:build !windows

/*
MIT License

Copyright (c) 2023-2024 The Trzsz SSH Authors.

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
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/creack/pty"
)

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
		defer c.stderr.Close()
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
		defer c.stdout.Close()
		defer close(doneCh)
		buf := make([]byte, 1000)
		n, err := c.stdout.Read(buf)
		if err != nil {
			doneCh <- fmt.Errorf("read stdout failed: %v", err)
			return
		}
		if !bytes.Equal(bytes.TrimSpace(buf[:n]), []byte("ok")) {
			doneCh <- fmt.Errorf("control master stdout invalid: %v", buf[:n])
			return
		}
		doneCh <- nil
	}()
	return doneCh
}

func (c *controlMaster) fillPassword(args *sshArgs, param *sshParam, expectCount int) (cancel context.CancelFunc) {
	var ctx context.Context
	expectTimeout := getExpectTimeout(args, "Ctrl")
	if expectTimeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), time.Duration(expectTimeout)*time.Second)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}

	expect := &sshExpect{
		param: param,
		args:  args,
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
			c.ptmx.Close()
		}
		exitCh <- struct{}{}
	}()
	return exitCh
}

func (c *controlMaster) start(args *sshArgs, param *sshParam) error {
	var err error
	c.cmd = exec.Command(c.path, c.args...)
	expectCount := getExpectCount(args, "Ctrl")
	if expectCount > 0 {
		c.cmd.SysProcAttr = &syscall.SysProcAttr{
			Setsid:  true,
			Setctty: true,
		}
		pty, tty, err := pty.Open()
		if err != nil {
			return fmt.Errorf("open pty failed: %v", err)
		}
		defer tty.Close()
		c.cmd.Stdin = tty
		c.ptmx = pty
		cancel := c.fillPassword(args, param, expectCount)
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
			onExitFuncs = append(onExitFuncs, func() {
				c.quit(exitCh)
			})
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

func getRealPath(path string) string {
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return path
	}
	return realPath
}

func getOpenSSH() (string, int, int, error) {
	sshPath := "/usr/bin/ssh"
	tsshPath, err := os.Executable()
	if err != nil {
		return "", 0, 0, err
	}
	if getRealPath(tsshPath) == getRealPath(sshPath) {
		return "", 0, 0, fmt.Errorf("%s is the current program", sshPath)
	}
	out, err := exec.Command(sshPath, "-V").CombinedOutput()
	if err != nil {
		return "", 0, 0, err
	}
	re := regexp.MustCompile(`OpenSSH_(\d+)\.(\d+)`)
	matches := re.FindStringSubmatch(string(out))
	majorVersion := -1
	minorVersion := -1
	if len(matches) > 2 {
		majorVersion, _ = strconv.Atoi(matches[1])
		minorVersion, _ = strconv.Atoi(matches[2])
	}
	return sshPath, majorVersion, minorVersion, nil
}

func startControlMaster(args *sshArgs, param *sshParam, sshPath string) error {
	cmdArgs := []string{"-T", "-oRemoteCommand=none", "-oConnectTimeout=10"}

	if args.Debug {
		cmdArgs = append(cmdArgs, "-v")
	}
	if !args.NoForwardAgent && args.ForwardAgent {
		cmdArgs = append(cmdArgs, "-A")
	}
	if args.LoginName != "" {
		cmdArgs = append(cmdArgs, "-l", args.LoginName)
	}
	if args.Port != 0 {
		cmdArgs = append(cmdArgs, "-p", strconv.Itoa(args.Port))
	}
	if args.ConfigFile != "" {
		cmdArgs = append(cmdArgs, "-F", args.ConfigFile)
	}
	if args.ProxyJump != "" {
		cmdArgs = append(cmdArgs, "-J", args.ProxyJump)
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
			break
		case "enabletrzsz", "enabledragfile":
			break
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
	if err := ctrlMaster.start(args, param); err != nil {
		return err
	}
	debug("start control master success")
	return nil
}

func connectViaControl(args *sshArgs, param *sshParam) SshClient {
	ctrlMaster := getOptionConfig(args, "ControlMaster")
	ctrlPath := getOptionConfig(args, "ControlPath")

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
	socket, err := expandTokens(ctrlPath, args, param, tokens)
	if err != nil {
		warning("expand ControlPath [%s] failed: %v", socket, err)
		return nil
	}
	socket = resolveHomeDir(socket)

	switch strings.ToLower(ctrlMaster) {
	case "yes", "ask":
		if isFileExist(socket) {
			warning("control socket [%s] already exists, disabling multiplexing", socket)
			return nil
		}
		fallthrough
	case "auto", "autoask":
		if err := startControlMaster(args, param, sshPath); err != nil {
			warning("start control master failed: %v", err)
		}
	}

	debug("login to [%s], socket: %s", args.Destination, socket)

	conn, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		warning("dial control socket [%s] failed: %v", socket, err)
		return nil
	}

	ncc, chans, reqs, err := NewControlClientConn(conn)
	if err != nil {
		warning("new conn from control socket [%s] failed: %v", socket, err)
		return nil
	}

	debug("login to [%s] success", args.Destination)
	return sshNewClient(ncc, chans, reqs)
}

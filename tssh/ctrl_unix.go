//go:build !windows

/*
MIT License

Copyright (c) 2023 Lonny Wong <lonnywong@qq.com>
Copyright (c) 2023 [Contributors](https://github.com/trzsz/trzsz-ssh/graphs/contributors)

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
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

type controlMaster struct {
	path      string
	args      []string
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	stdout    io.ReadCloser
	stderr    io.ReadCloser
	loggingIn atomic.Bool
	exited    atomic.Bool
}

func (c *controlMaster) readStderr() {
	go func() {
		defer c.stderr.Close()
		buf := make([]byte, 100)
		for c.loggingIn.Load() {
			n, err := c.stderr.Read(buf)
			if n > 0 {
				fmt.Fprintf(os.Stderr, "%s", string(buf[:n]))
			}
			if err != nil {
				break
			}
		}
	}()
}

func (c *controlMaster) readStdout() <-chan error {
	done := make(chan error, 1)
	go func() {
		defer close(done)
		buf := make([]byte, 1000)
		n, err := c.stdout.Read(buf)
		if err != nil {
			done <- fmt.Errorf("stdout read failed: %v", err)
			return
		}
		if !bytes.Equal(bytes.TrimSpace(buf[:n]), []byte("ok")) {
			done <- fmt.Errorf("stdout invalid: %v", buf[:n])
			return
		}
		done <- nil
	}()
	return done
}

func (c *controlMaster) checkExit() <-chan struct{} {
	exit := make(chan struct{}, 1)
	go func() {
		defer close(exit)
		_ = c.cmd.Wait()
		c.exited.Store(true)
		exit <- struct{}{}
	}()
	return exit
}

func (c *controlMaster) start() error {
	var err error
	c.cmd = exec.Command(c.path, c.args...)
	c.stdin, err = c.cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe failed: %v", err)
	}
	c.stdout, err = c.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe failed: %v", err)
	}
	c.stderr, err = c.cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe failed: %v", err)
	}
	if err := c.cmd.Start(); err != nil {
		return fmt.Errorf("start failed: %v", err)
	}

	c.loggingIn.Store(true)
	defer func() {
		c.loggingIn.Store(false)
	}()

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	defer func() { signal.Stop(interrupt); close(interrupt) }()

	c.readStderr()
	exit := c.checkExit()
	done := c.readStdout()

	onExitFuncs = append(onExitFuncs, func() {
		c.quit(exit)
	})

	for {
		select {
		case err := <-done:
			return err
		case <-exit:
			return fmt.Errorf("process exited")
		case <-interrupt:
			c.quit(exit)
			return fmt.Errorf("interrupt")
		}
	}
}

func (c *controlMaster) quit(exit <-chan struct{}) {
	if c.exited.Load() {
		return
	}
	_, _ = c.stdin.Write([]byte("\x03")) // ctrl + c
	_ = c.cmd.Process.Signal(syscall.SIGTERM)
	timer := time.AfterFunc(200*time.Millisecond, func() {
		_ = c.cmd.Process.Kill()
	})
	<-exit
	timer.Stop()
}

func getRealPath(path string) string {
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return path
	}
	return realPath
}

func getOpenSSH() (string, error) {
	sshPath := "/usr/bin/ssh"
	tsshPath, err := os.Executable()
	if err != nil {
		return "", err
	}
	if getRealPath(tsshPath) == getRealPath(sshPath) {
		return "", fmt.Errorf("%s is the current program", sshPath)
	}
	return sshPath, nil
}

func startControlMaster(args *sshArgs) {
	sshPath, err := getOpenSSH()
	if err != nil {
		warning("can't find ssh to start control master: %v", err)
		return
	}

	cmdArgs := []string{"-a", "-T", "-oClearAllForwardings=yes", "-oRemoteCommand=none", "-oConnectTimeout=5"}
	if args.Debug {
		cmdArgs = append(cmdArgs, "-v")
	}
	if args.LoginName != "" {
		cmdArgs = append(cmdArgs, "-l", args.LoginName)
	}
	if args.Port != 0 {
		cmdArgs = append(cmdArgs, "-p", strconv.Itoa(args.Port))
	}
	for _, identity := range args.Identity.values {
		cmdArgs = append(cmdArgs, "-i", identity)
	}
	if args.ConfigFile != "" {
		cmdArgs = append(cmdArgs, "-F", args.ConfigFile)
	}
	if args.ProxyJump != "" {
		cmdArgs = append(cmdArgs, "-J", args.ProxyJump)
	}

	for key, value := range args.Option.options {
		switch key {
		case "controlmaster":
			cmdArgs = append(cmdArgs, fmt.Sprintf("-oControlMaster=%s", value))
		case "controlpath":
			cmdArgs = append(cmdArgs, fmt.Sprintf("-oControlPath=%s", value))
		case "controlpersist":
			cmdArgs = append(cmdArgs, fmt.Sprintf("-oControlPersist=%s", value))
		}
	}

	if args.originalDest != "" {
		cmdArgs = append(cmdArgs, args.originalDest)
	} else {
		cmdArgs = append(cmdArgs, args.Destination)
	}
	// sleep 2147483 for PowerShell
	cmdArgs = append(cmdArgs, "echo ok; sleep 2147483; sleep infinity")

	if enableDebugLogging {
		debug("control master: %s %s", sshPath, strings.Join(cmdArgs, " "))
	}

	ctrlMaster := &controlMaster{path: sshPath, args: cmdArgs}
	if err := ctrlMaster.start(); err != nil {
		warning("start control master failed: %v", err)
		return
	}
	debug("start control master success")
}

func connectViaControl(args *sshArgs, param *loginParam) *ssh.Client {
	ctrlMaster := getOptionConfig(args, "ControlMaster")
	ctrlPath := getOptionConfig(args, "ControlPath")

	switch strings.ToLower(ctrlMaster) {
	case "auto", "yes", "ask", "autoask":
		startControlMaster(args)
	}

	switch strings.ToLower(ctrlPath) {
	case "", "none":
		return nil
	}

	unixAddr := resolveHomeDir(expandTokens(ctrlPath, args, param, "%CdhikLlnpru"))
	debug("login to [%s], socket: %s", args.Destination, unixAddr)

	conn, err := net.DialTimeout("unix", unixAddr, time.Second)
	if err != nil {
		warning("dial ctrl unix [%s] failed: %v", unixAddr, err)
		return nil
	}

	ncc, chans, reqs, err := NewControlClientConn(conn)
	if err != nil {
		warning("new ctrl conn [%s] failed: %v", unixAddr, err)
		return nil
	}

	debug("login to [%s] success", args.Destination)
	return ssh.NewClient(ncc, chans, reqs)
}

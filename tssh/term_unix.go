//go:build !windows

/*
MIT License

Copyright (c) 2023-2025 The Trzsz SSH Authors.

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
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/google/shlex"
	"golang.org/x/term"
)

type stdinState struct {
	state *term.State
}

func setupVirtualTerminal() error {
	return nil
}

func makeStdinRaw() (*stdinState, error) {
	state, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return nil, fmt.Errorf("terminal make raw failed: %v", err)
	}
	return &stdinState{state}, nil
}

func resetStdin(s *stdinState) {
	if s.state != nil {
		_ = term.Restore(int(os.Stdin.Fd()), s.state)
		s.state = nil
	}
}

func getTerminalSize() (int, int, error) {
	width, height, err := term.GetSize(int(os.Stdin.Fd()))
	if err != nil {
		return 0, 0, err
	}
	return width, height, nil
}

func onTerminalResize(setTerminalSize func(int, int)) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	go func() {
		for range ch {
			if width, height, err := term.GetSize(int(os.Stdin.Fd())); err == nil {
				setTerminalSize(width, height)
			}
		}
	}()
	ch <- syscall.SIGWINCH
}

func getKeyboardInput() (*os.File, func(), error) {
	if isTerminal {
		return os.Stdin, func() {}, nil
	}

	file, err := os.Open("/dev/tty")
	if err != nil {
		return nil, nil, err
	}

	return file, func() { _ = file.Close() }, nil
}

func isSshTmuxEnv() bool {
	if _, tmux := os.LookupEnv("TMUX"); !tmux {
		return false
	}

	cmd := exec.Command("tmux", "display-message", "-p", "#{client_pid}")
	cmd.Stdin = os.Stdin
	out, err := cmd.Output()
	if err != nil {
		return false
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return false
	}

	return isRemoteSshEnv(pid)
}

func splitCommandLine(command string) ([]string, error) {
	return shlex.Split(command)
}

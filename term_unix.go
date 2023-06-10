//go:build !windows

/*
MIT License

Copyright (c) 2023 Lonny Wong <lonnywong@qq.com>

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
	"os/signal"
	"syscall"

	"golang.org/x/term"
)

type terminalMode struct {
	state *term.State
}

func setupTerminalMode() (*terminalMode, error) {
	state, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return nil, fmt.Errorf("terminal make raw failed: %#v", err)
	}
	return &terminalMode{state}, nil
}

func resetTerminalMode(tm *terminalMode) {
	if tm.state != nil {
		_ = term.Restore(int(os.Stdin.Fd()), tm.state)
		tm.state = nil
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
			if width, height, err := term.GetSize(int(os.Stdin.Fd())); err != nil {
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

	path := "/dev/tty"
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}

	state, err := term.MakeRaw(int(file.Fd()))
	if err != nil {
		_ = file.Close()
		return nil, nil, fmt.Errorf("%s make raw failed: %#v", path, err)
	}

	return file, func() { _ = term.Restore(int(file.Fd()), state); _ = file.Close() }, nil
}

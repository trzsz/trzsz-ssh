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
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

type terminalMode struct {
	inCP    uint32
	outCP   uint32
	inMode  uint32
	outMode uint32
}

const CP_UTF8 uint32 = 65001

var kernel32 = windows.NewLazyDLL("kernel32.dll")

func getConsoleCP() uint32 {
	result, _, _ := kernel32.NewProc("GetConsoleCP").Call()
	return uint32(result)
}

func getConsoleOutputCP() uint32 {
	result, _, _ := kernel32.NewProc("GetConsoleOutputCP").Call()
	return uint32(result)
}

func setConsoleCP(cp uint32) {
	kernel32.NewProc("SetConsoleCP").Call(uintptr(cp))
}

func setConsoleOutputCP(cp uint32) {
	kernel32.NewProc("SetConsoleOutputCP").Call(uintptr(cp))
}

func enableVirtualTerminal() (uint32, uint32, error) {
	var inMode, outMode uint32
	inHandle, err := syscall.GetStdHandle(syscall.STD_INPUT_HANDLE)
	if err != nil {
		return 0, 0, err
	}
	if err := windows.GetConsoleMode(windows.Handle(inHandle), &inMode); err != nil {
		return 0, 0, err
	}
	if err := windows.SetConsoleMode(windows.Handle(inHandle), inMode|windows.ENABLE_VIRTUAL_TERMINAL_INPUT); err != nil {
		return 0, 0, err
	}

	outHandle, err := syscall.GetStdHandle(syscall.STD_OUTPUT_HANDLE)
	if err != nil {
		return 0, 0, err
	}
	if err := windows.GetConsoleMode(windows.Handle(outHandle), &outMode); err != nil {
		return 0, 0, err
	}
	if err := windows.SetConsoleMode(windows.Handle(outHandle),
		outMode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING|windows.DISABLE_NEWLINE_AUTO_RETURN); err != nil {
		return 0, 0, err
	}

	return inMode, outMode, nil
}

func resetVirtualTerminal(inMode, outMode uint32) error {
	inHandle, err := syscall.GetStdHandle(syscall.STD_INPUT_HANDLE)
	if err != nil {
		return err
	}
	if err := windows.SetConsoleMode(windows.Handle(inHandle), inMode); err != nil {
		return err
	}

	outHandle, err := syscall.GetStdHandle(syscall.STD_OUTPUT_HANDLE)
	if err != nil {
		return err
	}
	if err := windows.SetConsoleMode(windows.Handle(outHandle), outMode); err != nil {
		return err
	}

	return nil
}

func setupTerminalMode() (*terminalMode, error) {
	// enable virtual terminal
	inMode, outMode, err := enableVirtualTerminal()
	if err != nil {
		return nil, err
	}

	// set code page to UTF8
	inCP := getConsoleCP()
	outCP := getConsoleOutputCP()
	setConsoleCP(CP_UTF8)
	setConsoleOutputCP(CP_UTF8)

	return &terminalMode{inCP, outCP, inMode, outMode}, nil
}

func resetTerminalMode(t *terminalMode) {
	setConsoleCP(t.inCP)
	setConsoleOutputCP(t.outCP)
	resetVirtualTerminal(t.inMode, t.outMode)
}

func getTerminalSize() (int, int, error) {
	handle, err := syscall.GetStdHandle(syscall.STD_OUTPUT_HANDLE)
	if err != nil {
		return 0, 0, err
	}
	var info windows.ConsoleScreenBufferInfo
	if err := windows.GetConsoleScreenBufferInfo(windows.Handle(handle), &info); err != nil {
		return 0, 0, err
	}
	return int(info.Window.Right-info.Window.Left) + 1, int(info.Window.Bottom-info.Window.Top) + 1, nil
}

func onTerminalResize(setTerminalSize func(int, int)) {
	go func() {
		columns, rows, _ := getTerminalSize()
		for {
			time.Sleep(1 * time.Second)
			width, height, err := getTerminalSize()
			if err != nil {
				continue
			}
			if columns != width || rows != height {
				columns = width
				rows = height
				setTerminalSize(width, height)
			}
		}
	}()
}

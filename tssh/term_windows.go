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
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"golang.org/x/sys/windows"
	"golang.org/x/term"
)

var isRunningOnOldWindows atomic.Bool

type stdinState struct {
	state    *term.State
	settings *string
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

func enableVirtualTerminal() error {
	var inMode, outMode uint32
	inHandle, err := syscall.GetStdHandle(syscall.STD_INPUT_HANDLE)
	if err != nil {
		return err
	}
	if err := windows.GetConsoleMode(windows.Handle(inHandle), &inMode); err != nil {
		return err
	}
	addOnCloseFunc(func() { windows.SetConsoleMode(windows.Handle(inHandle), inMode) })
	if err := windows.SetConsoleMode(windows.Handle(inHandle), inMode|windows.ENABLE_VIRTUAL_TERMINAL_INPUT); err != nil {
		return err
	}

	outHandle, err := syscall.GetStdHandle(syscall.STD_OUTPUT_HANDLE)
	if err != nil {
		return err
	}
	if err := windows.GetConsoleMode(windows.Handle(outHandle), &outMode); err != nil {
		return err
	}
	addOnCloseFunc(func() { windows.SetConsoleMode(windows.Handle(outHandle), outMode) })
	if err := windows.SetConsoleMode(windows.Handle(outHandle),
		outMode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING|windows.DISABLE_NEWLINE_AUTO_RETURN); err != nil {
		return err
	}

	return nil
}

var sttyCommandExists *bool

func sttyExecutable() bool {
	if sttyCommandExists == nil {
		_, err := exec.LookPath("stty")
		exists := err == nil
		sttyCommandExists = &exists
	}
	return *sttyCommandExists
}

func sttySettings() (string, error) {
	cmd := exec.Command("stty", "-g")
	cmd.Stdin = os.Stdin
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func sttyMakeRaw() error {
	cmd := exec.Command("stty", "raw", "-echo")
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

func sttyReset(settings string) {
	cmd := exec.Command("stty", settings)
	cmd.Stdin = os.Stdin
	_ = cmd.Run()
}

func sttySize() (int, int, error) {
	cmd := exec.Command("stty", "size")
	cmd.Stdin = os.Stdin
	out, err := cmd.Output()
	if err != nil {
		return 0, 0, err
	}
	output := strings.TrimSpace(string(out))
	tokens := strings.Fields(output)
	if len(tokens) != 2 {
		return 0, 0, fmt.Errorf("stty size invalid: %s", output)
	}
	rows, err := strconv.ParseUint(tokens[0], 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("stty size invalid: %s", output)
	}
	cols, err := strconv.ParseUint(tokens[1], 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("stty size invalid: %s", output)
	}
	return int(cols), int(rows), nil
}

func setupVirtualTerminal() error {
	// enable virtual terminal
	if err := enableVirtualTerminal(); err != nil {
		if !sttyExecutable() {
			return fmt.Errorf("enable virtual terminal failed: %v\r\n%s", err,
				"Hint: You can try running tssh in Cygwin, MSYS2, or Git Bash.")
		}

		isRunningOnOldWindows.Store(true)
		lipgloss.SetColorProfile(termenv.ANSI256)

		if userConfig.promptCursorIcon == "" {
			promptCursorIcon = ">>"
		}
		if userConfig.promptSelectedIcon == "" {
			promptSelectedIcon = "++"
		}
	}

	// set code page to UTF8
	inCP := getConsoleCP()
	outCP := getConsoleOutputCP()
	setConsoleCP(CP_UTF8)
	setConsoleOutputCP(CP_UTF8)
	addOnCloseFunc(func() { setConsoleCP(inCP); setConsoleOutputCP(outCP) })

	return nil
}

func makeStdinRaw() (*stdinState, error) {
	state, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err == nil {
		return &stdinState{state, nil}, nil
	}

	if !sttyExecutable() {
		return nil, fmt.Errorf("terminal make raw failed: %v\r\n%s", err,
			"Hint: You can try running tssh in Cygwin, MSYS2, or Git Bash.")
	}

	isRunningOnOldWindows.Store(true)
	lipgloss.SetColorProfile(termenv.ANSI256)

	settings, err := sttySettings()
	if err != nil {
		return nil, fmt.Errorf("get stty settings failed: %v", err)
	}
	if err := sttyMakeRaw(); err != nil {
		return nil, fmt.Errorf("stty make raw failed: %v", err)
	}
	return &stdinState{nil, &settings}, nil
}

func resetStdin(s *stdinState) {
	if s.state != nil {
		_ = term.Restore(int(os.Stdin.Fd()), s.state)
		s.state = nil
	}
	if s.settings != nil {
		sttyReset(*s.settings)
		s.settings = nil
	}
}

func getTerminalSize() (int, int, error) {
	handle, err := syscall.GetStdHandle(syscall.STD_OUTPUT_HANDLE)
	if err != nil {
		if sttyExecutable() {
			return sttySize()
		}
		return 0, 0, err
	}
	var info windows.ConsoleScreenBufferInfo
	if err := windows.GetConsoleScreenBufferInfo(windows.Handle(handle), &info); err != nil {
		if sttyExecutable() {
			return sttySize()
		}
		return 0, 0, err
	}
	return int(info.Window.Right-info.Window.Left) + 1, int(info.Window.Bottom-info.Window.Top) + 1, nil
}

func onTerminalResize(setTerminalSize func(int, int)) {
	go func() {
		columns, rows, err := getTerminalSize()
		if err == nil {
			setTerminalSize(columns, rows)
		}
		for {
			time.Sleep(time.Second)
			width, height, err := getTerminalSize()
			if err != nil {
				continue
			}
			if columns != width || rows != height {
				columns, rows = width, height
				setTerminalSize(width, height)
			}
		}
	}()
}

func getKeyboardInput() (*os.File, func(), error) {
	if isTerminal {
		return os.Stdin, func() {}, nil
	}

	// O_RDWR is mandatory for capturing user keyboard input in non-terminal mode.
	// TEST: scp -S tssh xxx @xxx:/tmp/
	//       Enter passphrase for key xxx:
	file, err := os.OpenFile(`\\.\CONIN$`, os.O_RDWR, 0)
	if err != nil {
		return nil, nil, err
	}

	// file.Close() may block on Windows console handles (CONIN$).
	// it's safer to never close it and let the OS clean up on process exit.
	return file, func() {}, nil
}

func getStderrOutput() (*os.File, func(), error) {
	if isTerminal {
		return os.Stderr, func() {}, nil
	}

	file, err := os.OpenFile(`\\.\CONOUT$`, os.O_WRONLY, 0)
	if err != nil {
		return nil, nil, err
	}

	return file, func() { _ = file.Close() }, nil
}

type input_record struct {
	EventType uint16
	_         uint16 // padding
	Event     [16]byte
}

type key_event_record struct {
	KeyDown         int32
	RepeatCount     uint16
	VirtualKeyCode  uint16
	VirtualScanCode uint16
	UnicodeChar     uint16
	ControlKeyState uint32
}

func injectConsoleSpace() error {
	handle, err := syscall.GetStdHandle(syscall.STD_INPUT_HANDLE)
	if err != nil {
		return fmt.Errorf("get std handle failed: %v", err)
	}

	events := []input_record{
		makeSpaceKeyEvent(true),
		makeSpaceKeyEvent(false),
	}

	ret, _, err := kernel32.NewProc("WriteConsoleInputW").Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&events[0])),
		uintptr(len(events)),
		uintptr(unsafe.Pointer(new(uint32))),
	)

	if ret == 0 {
		return fmt.Errorf("write console input failed: %v", err)
	}
	return nil
}

func makeSpaceKeyEvent(down bool) input_record {
	var ir input_record
	ir.EventType = 0x0001 // KEY_EVENT

	ke := (*key_event_record)(unsafe.Pointer(&ir.Event[0]))
	if down {
		ke.KeyDown = 1
	}
	ke.RepeatCount = 1
	ke.VirtualKeyCode = 0x20 // VK_SPACE
	ke.UnicodeChar = uint16(' ')

	return ir
}

func splitCommandLine(command string) ([]string, error) {
	return windows.DecomposeCommandLine(command)
}

func suspendProcess() {
}

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
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

var enableDebugLogging bool = false
var envbleWarningLogging bool = true
var currentTerminalWidth atomic.Int32

const (
	kExitCodeArgsInvalid = 11
	kExitCodeUserConfig  = 12
	kExitCodeSetupWinVT  = 13
	kExitCodeNoDestHost  = 14
	kExitCodeBackground  = 15
	kExitCodeLoginFailed = 16
	kExitCodeIoFwFailed  = 17
	kExitCodeSubFwFailed = 18
	kExitCodeStartFailed = 19
	kExitCodeShellFailed = 20
	kExitCodeStdinFailed = 21
	kExitCodeTrzszFailed = 22

	kExitCodeToolsError  = 101
	kExitCodeTrzPreError = 102
	kExitCodeTrzRunError = 103
	kExitCodeTrzRetError = 104
	kExitCodeJsonMarshal = 105

	kExitCodeUdpCtrlC    = 201
	kExitCodeUdpTimeout  = 202
	kExitCodeConsoleKill = 203
)

var debug = func(format string, a ...any) {
	if !enableDebugLogging {
		return
	}
	fmt.Fprintf(os.Stderr, fmt.Sprintf("\033[0;36mdebug:\033[0m %s\r\n", format), a...)
}

var warning = func(format string, a ...any) {
	if !envbleWarningLogging {
		return
	}

	terminalWidth := int(currentTerminalWidth.Load())
	if terminalWidth <= 0 {
		fmt.Fprintf(os.Stderr, fmt.Sprintf("\033[0;33mWarning: %s\033[0m\r\n", format), a...)
		return
	}

	if enableDebugLogging {
		debug("warning: "+format, a...)
	}

	msg := fmt.Sprintf("Warning: "+format, a...)
	msgWidth := ansi.StringWidth(msg)
	if msgWidth > terminalWidth {
		msg = lipgloss.NewStyle().Foreground(blackColor).Background(yellowColor).Render(ansi.Truncate(msg, terminalWidth, ""))
	} else {
		msg = lipgloss.NewStyle().Foreground(blackColor).Width(terminalWidth).Background(yellowColor).Render(msg)
	}
	var buf strings.Builder
	buf.WriteString(ansi.SaveCurrentCursorPosition)
	buf.WriteString(ansi.CursorHomePosition)
	buf.WriteString(msg)
	buf.WriteString(ansi.EraseLineRight)
	buf.WriteString(ansi.RestoreCurrentCursorPosition)
	fmt.Fprint(os.Stderr, buf.String())
}

func isFileExist(path string) bool {
	stat, _ := os.Stat(path)
	if stat == nil {
		return false
	}
	return !stat.IsDir()
}

func isDirExist(path string) bool {
	stat, _ := os.Stat(path)
	if stat == nil {
		return false
	}
	return stat.IsDir()
}

func canReadFile(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	_ = file.Close()
	return true
}

func doWithTimeout[T any](task func() (T, error), timeout time.Duration) (T, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	done := make(chan struct {
		ret T
		err error
	}, 1)
	go func() {
		ret, err := task()
		done <- struct {
			ret T
			err error
		}{ret, err}
		close(done)
	}()
	select {
	case <-ctx.Done():
		var ret T
		return ret, fmt.Errorf("timeout exceeded %v", timeout)
	case res := <-done:
		return res.ret, res.err
	}
}

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
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

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
	kExitCodeOpenSession = 23

	kExitCodeToolsError  = 101
	kExitCodeTrzPreError = 102
	kExitCodeTrzRunError = 103
	kExitCodeTrzRetError = 104
	kExitCodeJsonMarshal = 105

	kExitCodeUdpCtrlC    = 201
	kExitCodeUdpTimeout  = 202
	kExitCodeConsoleKill = 203
	kExitCodeForceExit   = 204
	kExitCodeKeepAlive   = 205
	kExitCodeSignalKill  = 206
	kExitCodeTmuxDetach  = 207
)

var tmuxDebugPaneWriter io.Writer
var tmuxDebugPaneInited atomic.Bool

var enableDebugLogging bool = false
var enableWarningLogging bool = true
var currentTerminalWidth atomic.Int32

func initTmuxDebugPane() {
	if os.Getenv("TMUX") == "" {
		if runtime.GOOS != "windows" {
			_, _ = os.Stderr.WriteString("\r\033[42;30mFor better debugging: run `tmux` first, then `tssh --debug`.\033[K\033[0m\r\n")
		}
		return
	}

	out, err := exec.Command("tmux", "display-message", "-p", "#{pane_id}").Output()
	if err != nil {
		debug("tmux display message failed: %v", err)
		return
	}
	currentPaneId := strings.TrimSpace(string(out))

	out, err = exec.Command("tmux", "split-pane", "-h", "-p", "33", "-P", "-F", "#{pane_id}|#{pane_tty}").Output()
	if err != nil {
		debug("tmux split pane failed: %v", err)
		return
	}

	if err := exec.Command("tmux", "select-pane", "-t", currentPaneId).Run(); err != nil {
		debug("tmux select pane failed: %v", err)
		return
	}

	tokens := strings.Split(strings.TrimSpace(string(out)), "|")
	if len(tokens) != 2 {
		debug("tmux split pane result is not as expected: %v", tokens)
		return
	}

	debugPaneId, tty := tokens[0], tokens[1]
	addOnExitFunc(func() { _ = exec.Command("tmux", "kill-pane", "-t", debugPaneId).Run() })

	tmuxDebugPaneWriter, err = os.OpenFile(tty, os.O_WRONLY, 0)
	if err != nil {
		debug("open tmux tty [%s] failed: %v", tty, err)
		return
	}
}

func debug(format string, a ...any) {
	if !enableDebugLogging {
		return
	}

	msg := fmt.Sprintf(format, a...)
	buf := fmt.Appendf(nil, "\r\033[0;36mdebug:\033[0m %s\033[K\r\n", msg)

	if isRunningTmuxIntegration() {
		paneId, _ := getTmuxPaneIdAndColumns()
		if logToTmuxIntegration(buf, paneId) {
			return
		}
	}

	if tmuxDebugPaneInited.CompareAndSwap(false, true) {
		initTmuxDebugPane()
	}

	if tmuxDebugPaneWriter != nil {
		_, _ = tmuxDebugPaneWriter.Write(buf)
	} else {
		_, _ = os.Stderr.Write(buf)
	}
}

func warning(format string, a ...any) {
	if !enableWarningLogging {
		return
	}

	msg := "Warning: " + fmt.Sprintf(format, a...)

	terminalWidth := int(currentTerminalWidth.Load())
	if terminalWidth <= 0 {
		fmt.Fprintf(os.Stderr, "\r\033[0;33m%s\033[0m\033[K\r\n", msg)
		return
	}

	if enableDebugLogging {
		debug("warning: "+format, a...)
	}

	var paneId string
	tmux := isRunningTmuxIntegration()
	if tmux {
		paneId, terminalWidth = getTmuxPaneIdAndColumns()
		if terminalWidth <= 0 {
			terminalWidth = int(currentTerminalWidth.Load())
		}
	}

	msgWidth := ansi.StringWidth(msg)
	if msgWidth > terminalWidth {
		msg = lipgloss.NewStyle().Foreground(blackColor).Background(yellowColor).Render(ansi.Truncate(msg, terminalWidth, ""))
	} else {
		msg = lipgloss.NewStyle().Foreground(blackColor).Width(terminalWidth).Background(yellowColor).Render(msg)
	}
	var buf bytes.Buffer
	buf.WriteString(ansi.SaveCurrentCursorPosition)
	buf.WriteString(ansi.CursorHomePosition)
	buf.WriteString(msg)
	buf.WriteString(ansi.EraseLineRight)
	buf.WriteString(ansi.RestoreCurrentCursorPosition)

	if tmux && logToTmuxIntegration(buf.Bytes(), paneId) {
		return
	}

	_, _ = os.Stderr.Write(buf.Bytes())
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

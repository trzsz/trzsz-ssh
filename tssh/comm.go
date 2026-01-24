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
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"charm.land/lipgloss/v2"
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

var debugLogFile *os.File
var debugLogFileName string
var maxHostNameLength int
var debugStderrWriter *os.File
var debugWriteMutex sync.Mutex

var tmuxDebugPaneID string
var tmuxDebugPaneInited atomic.Bool
var tmuxDebugPaneWriter io.WriteCloser

var debugCleanuped atomic.Bool
var debugCleanupMu sync.Mutex
var debugCleanupWG sync.WaitGroup
var stdinInputChan atomic.Pointer[chan []byte]

var enableDebugLogging bool = false
var enableWarningLogging bool = true
var currentTerminalWidth atomic.Int32

func initDebugLogFile() bool {
	debugWriteMutex.Lock()
	if debugLogFile != nil {
		debugWriteMutex.Unlock()
		return true
	}

	var err error
	debugLogFile, err = os.CreateTemp("", "tssh_debug_*.log")
	if debugLogFile != nil {
		debugLogFileName = debugLogFile.Name()
	}

	debugWriteMutex.Unlock()

	if err != nil {
		debug("create debug log file failed: %v", err)
		return false
	}

	addOnExitFunc(cleanupDebugResources)
	return true
}

func closeDebugLogFile() {
	debugWriteMutex.Lock()
	defer debugWriteMutex.Unlock()

	if debugLogFile == nil {
		return
	}

	_ = debugLogFile.Close()
	debugLogFile = nil
}

func writeDebugLog(msec int64, host, log string) {
	if !enableDebugLogging {
		return
	}

	line := fmt.Sprintf("%s | %-*s | %s\n", time.UnixMilli(msec).Format("15:04:05.000"), maxHostNameLength, host, log)

	ok, err := func() (bool, error) {
		debugWriteMutex.Lock()
		defer debugWriteMutex.Unlock()
		if debugLogFile == nil {
			return false, nil
		}
		if _, err := debugLogFile.WriteString(line); err != nil {
			return false, fmt.Errorf("write debug log to [%s] failed: %v", debugLogFileName, err)
		}
		if err := debugLogFile.Sync(); err != nil {
			return false, fmt.Errorf("sync debug log to [%s] failed: %v", debugLogFileName, err)
		}
		return true, nil
	}()

	if err != nil {
		debug("%v", err)
	}
	if !ok {
		debug("%s", line[:len(line)-1])
	}
}

func initTmuxDebugPane() {
	if os.Getenv("TMUX") == "" {
		if runtime.GOOS != "windows" {
			_, _ = os.Stderr.WriteString("\r\033[42;30mFor better debugging: run `tmux` first, then `tssh --debug`.\033[0m\033[K\r\n")
		}
		return
	}

	if !initDebugLogFile() {
		return
	}

	out, err := exec.Command("tmux", "split-window", "-h", "-d", "-p", "33", "-P", "-F", "#{pane_id}|#{pane_tty}",
		"tail", "-f", debugLogFileName).Output()
	if err != nil {
		debug("tmux split pane failed: %v", err)
		return
	}

	tokens := strings.Split(strings.TrimSpace(string(out)), "|")
	if len(tokens) != 2 {
		debug("tmux split pane result is not as expected: %v", tokens)
		return
	}

	var tty string
	tmuxDebugPaneID, tty = tokens[0], tokens[1]
	tmuxDebugPaneWriter, err = os.OpenFile(tty, os.O_WRONLY, 0)
	if err != nil {
		debug("open tmux tty [%s] failed: %v", tty, err)
		return
	}
}

func cleanupDebugResources() {
	debugCleanupMu.Lock()
	defer debugCleanupMu.Unlock()
	if !debugCleanuped.CompareAndSwap(false, true) {
		return
	}

	debugCleanupWG.Add(1)
	defer debugCleanupWG.Done()

	// It’s possible that only the first hop has debug enabled while the following hops don’t.
	// Setting debug to true here ensures that data read by the stdin forwarding goroutine can be forwarded to this channel.
	enableDebugLogging = true
	ch := make(chan []byte, 10)
	stdinInputChan.Store(&ch)

	if isTerminal && runtime.GOOS == "windows" && !isRunningOnOldWindows.Load() {
		if err := injectConsoleSpace(); err != nil {
			debug("inject console space failed: %v", err)
		}
		// give the stdin forwarding goroutine time to read the injected space
		time.Sleep(10 * time.Millisecond)
	}

	stdin, closeStdin, err := getKeyboardInput()
	if err != nil {
		debug("get keyboard input failed: %v", err)
		return
	}
	defer closeStdin()

	stderr, closeStderr, err := getStderrOutput()
	if err != nil {
		debug("get stderr output failed: %v", err)
		return
	}
	defer closeStderr()

	go func() {
		buffer := make([]byte, 128)
		for {
			n, err := stdin.Read(buffer)
			if n > 0 {
				ch <- append([]byte(nil), buffer[:n]...)
			}
			if err != nil {
				break
			}
		}
	}()

	var inputBuffer []byte
	readLineFromStdin := func() (string, error) {
		for {
			data, ok := <-ch
			if !ok {
				if len(inputBuffer) > 0 {
					return string(inputBuffer), nil
				}
				return "", io.EOF
			}
			inputBuffer = append(inputBuffer, data...)
			if idx := bytes.IndexByte(inputBuffer, '\n'); idx >= 0 {
				line := string(inputBuffer[:idx])
				inputBuffer = inputBuffer[idx+1:]
				return line, nil
			}
		}
	}

	confirm := func(question string, defaultYes bool) bool {
		suffix := "[yes/No]:"
		if defaultYes {
			suffix = "[Yes/no]:"
		}
		prompt := fmt.Sprintf("%s %s ", question, suffix)
		for {
			_, _ = stderr.WriteString(prompt)
			input, err := readLineFromStdin()
			if err != nil {
				debug("read input failed: %v", err)
				return defaultYes
			}

			input = strings.ToLower(strings.TrimSpace(input))
			switch input {
			case "":
				return defaultYes
			case "y", "yes":
				return true
			case "n", "no":
				return false
			default:
				_, _ = stderr.WriteString("Please enter yes (y) or no (n).\r\n")
			}
		}
	}

	if tmuxDebugPaneID != "" && confirm("Do you want to close the debug pane?", true) {
		debugWriteMutex.Lock()
		if tmuxDebugPaneWriter != nil {
			_ = tmuxDebugPaneWriter.Close()
			tmuxDebugPaneWriter = nil
		}
		debugWriteMutex.Unlock()
		_ = exec.Command("tmux", "kill-pane", "-t", tmuxDebugPaneID).Run()
	}

	closeDebugLogFile()

	if debugLogFileName != "" {
		var deleteLogFile bool
		if stat, err := os.Stat(debugLogFileName); err == nil {
			if stat.Size() == 0 {
				deleteLogFile = true
			} else if confirm(fmt.Sprintf("Do you want to delete the debug log [%s]?", debugLogFileName), false) {
				deleteLogFile = true
			}
		}

		if deleteLogFile {
			if err := os.Remove(debugLogFileName); err != nil {
				debug("delete log file [%s] failed: %v", debugLogFileName, err)
			}
		}
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

	debugWriteMutex.Lock()
	defer debugWriteMutex.Unlock()
	if tmuxDebugPaneWriter != nil {
		_, _ = tmuxDebugPaneWriter.Write(buf)
	} else {
		if debugStderrWriter == nil {
			var err error
			debugStderrWriter, _, err = getStderrOutput()
			if err != nil {
				fmt.Fprintf(os.Stderr, "\r\033[0;36mdebug:\033[0m get stderr output failed: %v\033[K\r\n", err)
				debugStderrWriter = os.Stderr
			}
		}
		_, _ = debugStderrWriter.Write(buf)
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

// delayWarning delays printing the warning message to improve its visibility.
// In some cases a warning message may be printed on the first line at the top
// and immediately followed by other output, causing the warning message to be
// scrolled out of view. Delaying the emission may help mitigate this issue and
// improve warning visibility during subsequent scroll output.
func delayWarning(delayTime time.Duration, format string, a ...any) {
	if !enableWarningLogging {
		return
	}

	go func() {
		time.Sleep(delayTime)
		warning(format, a...)
	}()
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

var runningInRemoteSshOnce sync.Once
var runningInRemoteSshFlag atomic.Bool

func isRunningInRemoteSsh() bool {
	runningInRemoteSshOnce.Do(func() {
		runningInRemoteSshFlag.Store(isRemoteSshEnv(os.Getpid()))
	})
	return runningInRemoteSshFlag.Load()
}

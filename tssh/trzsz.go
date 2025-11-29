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
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/trzsz/trzsz-go/trzsz"
)

var pauseOutput atomic.Bool
var outputWaitGroup sync.WaitGroup

func writeAll(dst io.Writer, data []byte) error {
	m := 0
	l := len(data)
	for m < l {
		n, err := dst.Write(data[m:])
		if err != nil {
			return err
		}
		m += n
	}
	return nil
}

func forwardInput(reader io.Reader, writer io.WriteCloser, win bool, escapeChar byte, escapeTime time.Duration, ss *sshClientSession) {
	defer func() { _ = writer.Close() }()
	var enterPressedFlag bool
	var enterPressedTime time.Time
	buffer := make([]byte, 32*1024)
	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			if escapeTime > 0 { // enter tssh console ?
				if n == 1 && buffer[0] == '\r' {
					enterPressedFlag = true
					enterPressedTime = time.Now()
				} else if enterPressedFlag && n == 1 && buffer[0] == escapeChar && time.Since(enterPressedTime) <= escapeTime {
					pauseOutput.Store(true)
					runConsole(escapeChar, reader, writer, ss)
					pauseOutput.Store(false)
					continue
				} else {
					enterPressedFlag = false
				}
			}

			buf := buffer[:n]
			if win && !ss.tty {
				buf = bytes.ReplaceAll(buf, []byte("\r\n"), []byte("\n"))
			}
			if err := writeAll(writer, buf); err != nil {
				warning("wrap input write failed: %v", err)
				return
			}
		}
		if err == io.EOF {
			if win && isTerminal && ss.tty {
				_, _ = writer.Write([]byte{0x1A}) // ctrl + z
				continue
			}
			return
		}
		if err != nil {
			return
		}
	}
}

func forwardOutput(reader io.Reader, writer io.WriteCloser, win, tty bool) {
	// Don't close os.Stdout and os.Stderr here.
	// There may be some debugging message that needs to be output.
	// The process is about to exit, so let the operating system close os.Stdout and os.Stderr.
	buffer := make([]byte, 32*1024)
	for {
		n, err := reader.Read(buffer)
		for pauseOutput.Load() {
			time.Sleep(10 * time.Millisecond)
		}
		if n > 0 {
			buf := buffer[:n]
			if win && !tty {
				buf = bytes.ReplaceAll(buf, []byte("\n"), []byte("\r\n"))
			}
			if err := writeAll(writer, buf); err != nil {
				warning("wrap output write failed: %v", err)
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func wrapStdIO(serverIn io.WriteCloser, serverOut, serverErr io.Reader, escapeChar byte, escapeTime time.Duration, ss *sshClientSession) {
	win := runtime.GOOS == "windows"
	if serverIn != nil {
		go forwardInput(os.Stdin, serverIn, win, escapeChar, escapeTime, ss)
	}

	if serverOut != nil {
		outputWaitGroup.Go(func() { forwardOutput(serverOut, os.Stdout, win, ss.tty) })
	}
	if serverErr != nil {
		outputWaitGroup.Go(func() { forwardOutput(serverErr, os.Stderr, win, ss.tty) })
	}
}

func getEscapeConfig(args *sshArgs) (byte, time.Duration) {
	consoleEscapeTime := time.Second
	if t := getExOptionConfig(args, "ConsoleEscapeTime"); t != "" {
		v, err := strconv.ParseUint(t, 10, 32)
		if err != nil {
			warning("ConsoleEscapeTime [%s] is invalid: %v", t, err)
		} else {
			consoleEscapeTime = time.Duration(v) * time.Second
		}
	}

	escapeChar := byte('~')
	if escCh := getOptionConfig(args, "EscapeChar"); escCh != "" {
		if strings.ToLower(escCh) == "none" {
			consoleEscapeTime = 0
		} else if len(escCh) == 2 && escCh[0] == '^' {
			b := escCh[1]
			switch b {
			case 'z', 'Z', 'c', 'C':
				warning("EscapeChar [%s] conflicts with other shortcuts", escCh)
			default:
				if b >= 'a' && b <= 'z' {
					escapeChar = b - 'a' + 1
				} else if b >= 'A' && b <= 'Z' {
					escapeChar = b - 'A' + 1
				} else {
					warning("EscapeChar [%s] is not a valid letter following ^", escCh)
				}
			}
		} else if len(escCh) == 1 {
			b := escCh[0]
			switch b {
			case 'j', 'k', 'q', '.', 'B', 'C', 'R', 'V', 'v', '#', '&', '?':
				warning("EscapeChar [%s] conflicts with other shortcuts", escCh)
			default:
				if b <= ' ' || b > '~' {
					warning("EscapeChar [%s] is not a valid visible character", escCh)
				} else {
					escapeChar = b
				}
			}
		} else {
			warning("EscapeChar [%s] is not a single character or ‘^’ followed by a letter", escCh)
		}
	}

	return escapeChar, consoleEscapeTime
}

func enableTrzsz(args *sshArgs, ss *sshClientSession) error {
	// not terminal or not tty
	if !isTerminal || !ss.tty {
		wrapStdIO(ss.serverIn, ss.serverOut, ss.serverErr, 0, 0, ss)
		return nil
	}

	escapeChar, consoleEscapeTime := getEscapeConfig(args)

	disableTrzsz := strings.ToLower(getExOptionConfig(args, "EnableTrzsz")) == "no"
	enableZmodem := args.Zmodem || strings.ToLower(getExOptionConfig(args, "EnableZmodem")) == "yes"
	enableDragFile := args.DragFile || strings.ToLower(getExOptionConfig(args, "EnableDragFile")) == "yes"
	enableOSC52 := strings.ToLower(getExOptionConfig(args, "EnableOSC52")) == "yes"

	// disable trzsz ( trz / tsz )
	if disableTrzsz && !enableZmodem && !enableDragFile && !enableOSC52 {
		wrapStdIO(ss.serverIn, ss.serverOut, ss.serverErr, escapeChar, consoleEscapeTime, ss)
		onTerminalResize(func(width, height int) {
			currentTerminalWidth.Store(int32(width))
			_ = ss.session.WindowChange(height, width)
		})
		return nil
	}

	// support trzsz ( trz / tsz )
	var clientIn io.Reader
	var clientOut io.WriteCloser
	if consoleEscapeTime > 0 {
		readerIn, writerIn := io.Pipe()
		readerOut, writerOut := io.Pipe()
		clientIn, clientOut = readerIn, writerOut
		wrapStdIO(writerIn, readerOut, ss.serverErr, escapeChar, consoleEscapeTime, ss)
	} else {
		clientIn, clientOut = os.Stdin, os.Stdout
		wrapStdIO(nil, nil, ss.serverErr, 0, 0, ss)
	}

	trzsz.SetAffectedByWindows(false)

	if args.Relay || !args.Client && isNoGUI() {
		// run as a relay
		trzszRelay := trzsz.NewTrzszRelay(clientIn, clientOut, ss.serverIn, ss.serverOut, trzsz.TrzszOptions{
			DetectTraceLog: args.TraceLog,
		})
		// close on exit
		addOnExitFunc(func() { trzszRelay.Close() })
		// reset terminal size on resize
		onTerminalResize(func(width, height int) {
			currentTerminalWidth.Store(int32(width))
			_ = ss.session.WindowChange(height, width)
		})
		// setup tunnel connect
		trzszRelay.SetTunnelConnector(func(port int) net.Conn {
			conn, _ := ss.client.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
			return conn
		})
		return nil
	}

	width, _, err := getTerminalSize()
	if err != nil {
		return fmt.Errorf("get terminal size failed: %v", err)
	}

	// custom configuration
	defaultUploadPath := getExOptionConfig(args, "DefaultUploadPath")
	if defaultUploadPath == "" {
		defaultUploadPath = userConfig.defaultUploadPath
	}
	defaultDownloadPath := args.DownloadPath
	if defaultDownloadPath == "" {
		defaultDownloadPath = getExOptionConfig(args, "DefaultDownloadPath")
		if defaultDownloadPath == "" {
			defaultDownloadPath = userConfig.defaultDownloadPath
		}
	}
	dragFileUploadCommand := getExOptionConfig(args, "DragFileUploadCommand")
	if dragFileUploadCommand == "" {
		dragFileUploadCommand = userConfig.dragFileUploadCommand
	}

	// create a TrzszFilter to support trzsz ( trz / tsz )
	//
	//   os.Stdin  ┌────────┐   os.Stdin   ┌─────────────┐   ServerIn   ┌────────┐
	// ───────────►│        ├─────────────►│             ├─────────────►│        │
	//             │        │              │ TrzszFilter │              │        │
	// ◄───────────│ Client │◄─────────────┤             │◄─────────────┤ Server │
	//   os.Stdout │        │   os.Stdout  └─────────────┘   ServerOut  │        │
	// ◄───────────│        │◄──────────────────────────────────────────┤        │
	//   os.Stderr └────────┘                  stderr                   └────────┘
	trzszFilter := trzsz.NewTrzszFilter(clientIn, clientOut, ss.serverIn, ss.serverOut, trzsz.TrzszOptions{
		TerminalColumns: int32(width),
		DetectDragFile:  enableDragFile,
		DetectTraceLog:  args.TraceLog,
		EnableZmodem:    enableZmodem,
		EnableOSC52:     enableOSC52,
	})

	// reset terminal and close on exit
	addOnExitFunc(func() { trzszFilter.ResetTerminal(); trzszFilter.Close() })

	// reset terminal size on resize
	onTerminalResize(func(width, height int) {
		currentTerminalWidth.Store(int32(width))
		trzszFilter.SetTerminalColumns(int32(width))
		_ = ss.session.WindowChange(height, width)
	})

	// setup trzsz config
	trzszFilter.SetDefaultUploadPath(defaultUploadPath)
	trzszFilter.SetDefaultDownloadPath(defaultDownloadPath)
	trzszFilter.SetDragFileUploadCommand(dragFileUploadCommand)
	trzszFilter.SetProgressColorPair(userConfig.progressColorPair)

	// setup tunnel connect
	trzszFilter.SetTunnelConnector(func(port int) net.Conn {
		conn, _ := ss.client.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		return conn
	})

	// setup redraw screen
	trzszFilter.SetRedrawScreenFunc(ss.session.RedrawScreen)

	return nil
}

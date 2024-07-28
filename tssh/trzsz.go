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
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/trzsz/trzsz-go/trzsz"
)

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

func wrapStdIO(serverIn io.WriteCloser, serverOut io.Reader, serverErr io.Reader, tty bool) {
	win := runtime.GOOS == "windows"
	forwardIO := func(reader io.Reader, writer io.WriteCloser, input bool) {
		done := true
		if !input {
			done = false
			outputWaitGroup.Add(1)
		}
		defer writer.Close()
		buffer := make([]byte, 32*1024)
		for {
			n, err := reader.Read(buffer)
			if n > 0 {
				buf := buffer[:n]
				if win && !tty {
					if input {
						buf = bytes.ReplaceAll(buf, []byte("\r\n"), []byte("\n"))
					} else {
						buf = bytes.ReplaceAll(buf, []byte("\n"), []byte("\r\n"))
					}
				}
				if err := writeAll(writer, buf); err != nil {
					warning("wrap stdio write failed: %v", err)
					return
				}
			}
			if err == io.EOF {
				if win && isTerminal && tty && input {
					_, _ = writer.Write([]byte{0x1A}) // ctrl + z
					continue
				}
				if input {
					return // input EOF
				}
				// ignore output EOF
				if !done {
					outputWaitGroup.Done()
					done = true
				}
				time.Sleep(100 * time.Millisecond)
				continue
			}
			if err != nil {
				return
			}
		}
	}
	if serverIn != nil {
		go forwardIO(os.Stdin, serverIn, true)
	}
	if serverOut != nil {
		go forwardIO(serverOut, os.Stdout, false)
	}
	if serverErr != nil {
		go forwardIO(serverErr, os.Stderr, false)
	}
}

func enableTrzsz(args *sshArgs, ss *sshClientSession) error {
	// not terminal or not tty
	if !isTerminal || !ss.tty {
		wrapStdIO(ss.serverIn, ss.serverOut, ss.serverErr, ss.tty)
		return nil
	}

	disableTrzsz := strings.ToLower(getExOptionConfig(args, "EnableTrzsz")) == "no"
	enableZmodem := args.Zmodem || strings.ToLower(getExOptionConfig(args, "EnableZmodem")) == "yes"
	enableDragFile := args.DragFile || strings.ToLower(getExOptionConfig(args, "EnableDragFile")) == "yes"
	enableOSC52 := strings.ToLower(getExOptionConfig(args, "EnableOSC52")) == "yes"

	// disable trzsz ( trz / tsz )
	if disableTrzsz && !enableZmodem && !enableDragFile && !enableOSC52 {
		wrapStdIO(ss.serverIn, ss.serverOut, ss.serverErr, ss.tty)
		onTerminalResize(func(width, height int) { _ = ss.session.WindowChange(height, width) })
		return nil
	}

	// support trzsz ( trz / tsz )

	wrapStdIO(nil, nil, ss.serverErr, ss.tty)

	trzsz.SetAffectedByWindows(false)

	if args.Relay || !args.Client && isNoGUI() {
		// run as a relay
		trzszRelay := trzsz.NewTrzszRelay(os.Stdin, os.Stdout, ss.serverIn, ss.serverOut, trzsz.TrzszOptions{
			DetectTraceLog: args.TraceLog,
		})
		// reset terminal size on resize
		onTerminalResize(func(width, height int) { _ = ss.session.WindowChange(height, width) })
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

	// create a TrzszFilter to support trzsz ( trz / tsz )
	//
	//   os.Stdin  ┌────────┐   os.Stdin   ┌─────────────┐   ServerIn   ┌────────┐
	// ───────────►│        ├─────────────►│             ├─────────────►│        │
	//             │        │              │ TrzszFilter │              │        │
	// ◄───────────│ Client │◄─────────────┤             │◄─────────────┤ Server │
	//   os.Stdout │        │   os.Stdout  └─────────────┘   ServerOut  │        │
	// ◄───────────│        │◄──────────────────────────────────────────┤        │
	//   os.Stderr └────────┘                  stderr                   └────────┘
	trzszFilter := trzsz.NewTrzszFilter(os.Stdin, os.Stdout, ss.serverIn, ss.serverOut, trzsz.TrzszOptions{
		TerminalColumns: int32(width),
		DetectDragFile:  enableDragFile,
		DetectTraceLog:  args.TraceLog,
		EnableZmodem:    enableZmodem,
		EnableOSC52:     enableOSC52,
	})

	// reset terminal on exit
	onExitFuncs = append(onExitFuncs, func() {
		trzszFilter.ResetTerminal()
	})

	// reset terminal size on resize
	onTerminalResize(func(width, height int) {
		trzszFilter.SetTerminalColumns(int32(width))
		_ = ss.session.WindowChange(height, width)
	})

	// setup trzsz config
	trzszFilter.SetDefaultUploadPath(userConfig.defaultUploadPath)

	downloadPath := args.DownloadPath
	if downloadPath == "" {
		downloadPath = userConfig.defaultDownloadPath
	}
	trzszFilter.SetDefaultDownloadPath(downloadPath)

	dragFileUploadCommand := getExOptionConfig(args, "DragFileUploadCommand")
	if dragFileUploadCommand == "" {
		dragFileUploadCommand = userConfig.dragFileUploadCommand
	}
	trzszFilter.SetDragFileUploadCommand(dragFileUploadCommand)

	trzszFilter.SetProgressColorPair(userConfig.progressColorPair)

	// setup tunnel connect
	trzszFilter.SetTunnelConnector(func(port int) net.Conn {
		conn, _ := ss.client.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		return conn
	})

	return nil
}

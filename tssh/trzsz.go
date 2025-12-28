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
	"io"
	"net"
	"strings"
	"time"

	"github.com/trzsz/trzsz-go/trzsz"
)

func setupTrzszFilter(sshConn *sshConnection) error {
	// not terminal or not tty
	if !isTerminal || !sshConn.tty {
		return nil
	}

	args := sshConn.param.args
	disableTrzsz := strings.ToLower(getExOptionConfig(args, "EnableTrzsz")) == "no"
	enableZmodem := args.Zmodem || strings.ToLower(getExOptionConfig(args, "EnableZmodem")) == "yes"
	enableDragFile := args.DragFile || strings.ToLower(getExOptionConfig(args, "EnableDragFile")) == "yes"
	enableOSC52 := strings.ToLower(getExOptionConfig(args, "EnableOSC52")) == "yes"

	// disable trzsz ( trz / tsz )
	if disableTrzsz && !enableZmodem && !enableDragFile && !enableOSC52 {
		onTerminalResize(func(width, height int) {
			currentTerminalWidth.Store(int32(width))
			_ = sshConn.session.WindowChange(height, width)
		})
		return nil
	}

	// support trzsz ( trz / tsz )
	clientIn, writerIn := io.Pipe()
	readerOut, clientOut := io.Pipe()
	serverIn, serverOut := sshConn.serverIn, sshConn.serverOut
	sshConn.serverIn, sshConn.serverOut = writerIn, readerOut

	trzsz.SetAffectedByWindows(false)

	if args.Relay || !args.Client && isNoGUI() {
		// run as a relay
		trzszRelay := trzsz.NewTrzszRelay(clientIn, clientOut, serverIn, serverOut, trzsz.TrzszOptions{
			DetectTraceLog: args.TraceLog,
		})
		// close on exit
		addOnExitFunc(func() { trzszRelay.Close() })
		// reset terminal size on resize
		onTerminalResize(func(width, height int) {
			currentTerminalWidth.Store(int32(width))
			_ = sshConn.session.WindowChange(height, width)
		})
		// setup tunnel connect
		trzszRelay.SetTunnelConnector(func(port int) net.Conn {
			conn, _ := sshConn.client.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
			return conn
		})
		// setup transfer state callback
		if lastJumpUdpClient != nil {
			trzszRelay.SetTransferStateCallback(func(transferring bool) {
				_ = lastJumpUdpClient.SetKeepPendingInput(transferring)
				_ = lastJumpUdpClient.SetKeepPendingOutput(transferring)
			})
		}
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
	trzszFilter := trzsz.NewTrzszFilter(clientIn, clientOut, serverIn, serverOut, trzsz.TrzszOptions{
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
		_ = sshConn.session.WindowChange(height, width)
	})

	// setup trzsz config
	trzszFilter.SetDefaultUploadPath(defaultUploadPath)
	trzszFilter.SetDefaultDownloadPath(defaultDownloadPath)
	trzszFilter.SetDragFileUploadCommand(dragFileUploadCommand)
	trzszFilter.SetProgressColorPair(userConfig.progressColorPair)

	// setup tunnel connect
	trzszFilter.SetTunnelConnector(func(port int) net.Conn {
		conn, _ := sshConn.client.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		return conn
	})

	// setup redraw screen
	trzszFilter.SetRedrawScreenFunc(sshConn.session.RedrawScreen)

	// setup transfer state callback
	if lastJumpUdpClient != nil {
		trzszFilter.SetTransferStateCallback(func(transferring bool) {
			_ = lastJumpUdpClient.SetKeepPendingInput(transferring)
			_ = lastJumpUdpClient.SetKeepPendingOutput(transferring)
		})
	}

	return nil
}

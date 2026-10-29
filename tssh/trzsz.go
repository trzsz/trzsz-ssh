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
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/trzsz/trzsz-go/trzsz"
)

// trzszSettings holds the trzsz related options of a host.
type trzszSettings struct {
	disableTrzsz          bool
	enableZmodem          bool
	enableDragFile        bool
	enableOSC52           bool
	relay                 bool
	allowedAutoUploadDirs string
	defaultUploadPath     string
	defaultDownloadPath   string
	dragFileUploadCommand string
}

func getTrzszSettings(args *sshArgs) *trzszSettings {
	s := &trzszSettings{
		disableTrzsz:   strings.EqualFold(getExOptionConfig(args, "EnableTrzsz"), "no"),
		enableZmodem:   args.Zmodem || strings.EqualFold(getExOptionConfig(args, "EnableZmodem"), "yes"),
		enableDragFile: args.DragFile || strings.EqualFold(getExOptionConfig(args, "EnableDragFile"), "yes"),
		enableOSC52:    strings.EqualFold(getExOptionConfig(args, "EnableOSC52"), "yes"),
		relay:          args.Relay || !args.Client && isNoGUI(),
	}
	s.allowedAutoUploadDirs = getExOptionConfig(args, "AllowedAutoUploadDirs")
	if strings.EqualFold(s.allowedAutoUploadDirs, "none") {
		s.allowedAutoUploadDirs = ""
	} else if s.allowedAutoUploadDirs == "" {
		s.allowedAutoUploadDirs = userConfig.allowedAutoUploadDirs
	}
	s.defaultUploadPath = getExOptionConfig(args, "DefaultUploadPath")
	if s.defaultUploadPath == "" {
		s.defaultUploadPath = userConfig.defaultUploadPath
	}
	s.defaultDownloadPath = args.DownloadPath
	if s.defaultDownloadPath == "" {
		s.defaultDownloadPath = getExOptionConfig(args, "DefaultDownloadPath")
		if s.defaultDownloadPath == "" {
			s.defaultDownloadPath = userConfig.defaultDownloadPath
		}
	}
	s.dragFileUploadCommand = getExOptionConfig(args, "DragFileUploadCommand")
	if s.dragFileUploadCommand == "" {
		s.dragFileUploadCommand = userConfig.dragFileUploadCommand
	}
	return s
}

// enabled reports whether any trzsz feature is turned on.
func (s *trzszSettings) enabled() bool {
	return !s.disableTrzsz || s.enableZmodem || s.enableDragFile || s.enableOSC52
}

// newFilter creates a TrzszFilter between the client streams and the session streams.
func (s *trzszSettings) newFilter(args *sshArgs, client SshClient, session SshSession,
	clientIn io.Reader, clientOut io.WriteCloser, serverIn io.WriteCloser, serverOut io.Reader, width int) *trzsz.TrzszFilter {
	trzsz.SetAffectedByWindows(false)

	//   clientIn  ┌────────┐   clientIn   ┌─────────────┐   serverIn   ┌────────┐
	// ───────────►│        ├─────────────►│             ├─────────────►│        │
	//             │        │              │ TrzszFilter │              │        │
	// ◄───────────│ Client │◄─────────────┤             │◄─────────────┤ Server │
	//   clientOut │        │   clientOut  └─────────────┘   serverOut  │        │
	// ◄───────────│        │◄──────────────────────────────────────────┤        │
	//   stderr    └────────┘                  stderr                   └────────┘
	trzszFilter := trzsz.NewTrzszFilter(clientIn, clientOut, serverIn, serverOut, trzsz.TrzszOptions{
		TerminalColumns: int32(width),
		DetectDragFile:  s.enableDragFile,
		DetectTraceLog:  args.TraceLog,
		EnableZmodem:    s.enableZmodem,
		EnableOSC52:     s.enableOSC52,
	})

	if err := trzszFilter.SetAllowedAutoUploadDirs(s.allowedAutoUploadDirs); err != nil {
		warning("AllowedAutoUploadDirs %q is invalid: %v", s.allowedAutoUploadDirs, err)
	}
	if err := trzszFilter.SetDefaultUploadPath(s.defaultUploadPath); err != nil {
		warning("DefaultUploadPath %q is invalid: %v", s.defaultUploadPath, err)
	}
	if err := trzszFilter.SetDefaultDownloadPath(s.defaultDownloadPath); err != nil {
		warning("DefaultDownloadPath %q is invalid: %v", s.defaultDownloadPath, err)
	}
	trzszFilter.SetDragFileUploadCommand(s.dragFileUploadCommand)
	trzszFilter.SetProgressColorPair(userConfig.progressColorPair)

	if s.enableZmodem {
		autoRename := getExOptionConfig(args, "ZmodemAutoRename")
		if autoRename == "" {
			autoRename = userConfig.zmodemAutoRename
		}
		if autoRename != "" {
			trzszFilter.SetZmodemAutoRename(*parseBoolValue("ZmodemAutoRename", autoRename, false))
		}
	}

	trzszFilter.SetTunnelConnector(func(port int) net.Conn {
		conn, _ := client.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		return conn
	})
	trzszFilter.SetRedrawScreenFunc(func() { _ = session.RedrawScreen(true) })

	// keep the udp transport from dropping pending data while a transfer is running
	if lastJumpUdpClient != nil {
		trzszFilter.SetTransferStateCallback(func(transferring bool) {
			_ = lastJumpUdpClient.SetKeepPendingInput(transferring)
			_ = lastJumpUdpClient.SetKeepPendingOutput(transferring)
		})
	}
	return trzszFilter
}

func setupTrzszFilter(sshConn *sshConnection) error {
	// not terminal or not tty
	if !isTerminal || !sshConn.tty {
		return nil
	}

	args := sshConn.param.args
	settings := getTrzszSettings(args)

	// disable trzsz ( trz / tsz )
	if !settings.enabled() {
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

	if settings.relay {
		// run as a relay
		trzsz.SetAffectedByWindows(false)
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

	// create a TrzszFilter to support trzsz ( trz / tsz )
	trzszFilter := settings.newFilter(args, sshConn.client, sshConn.session, clientIn, clientOut, serverIn, serverOut, width)

	// reset terminal and close on exit
	addOnExitFunc(func() { trzszFilter.ResetTerminal(); trzszFilter.Close() })

	// reset terminal size on resize
	onTerminalResize(func(width, height int) {
		currentTerminalWidth.Store(int32(width))
		trzszFilter.SetTerminalColumns(int32(width))
		_ = sshConn.session.WindowChange(height, width)
	})

	return nil
}

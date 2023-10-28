/*
MIT License

Copyright (c) 2023 Lonny Wong <lonnywong@qq.com>
Copyright (c) 2023 [Contributors](https://github.com/trzsz/trzsz-ssh/graphs/contributors)

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
	"time"

	"github.com/trzsz/trzsz-go/trzsz"
	"golang.org/x/crypto/ssh"
)

func wrapStdIO(serverIn io.WriteCloser, serverOut io.Reader, tty bool) {
	win := runtime.GOOS == "windows"
	forwardIO := func(reader io.Reader, writer io.WriteCloser, oldVal, newVal []byte) {
		defer writer.Close()
		buffer := make([]byte, 32*1024)
		for {
			n, err := reader.Read(buffer)
			if n > 0 {
				buf := buffer[:n]
				if win && !tty {
					buf = bytes.ReplaceAll(buf, oldVal, newVal)
				}
				w := 0
				for w < len(buf) {
					n, err := writer.Write(buf[w:])
					if err != nil {
						warning("wrap stdio write failed: %v", err)
						return
					}
					w += n
				}
			}
			if err == io.EOF {
				if win && tty {
					_, _ = writer.Write([]byte{0x1A}) // ctrl + z
					continue
				}
				break
			}
			if err != nil {
				warning("wrap stdio read failed: %v", err)
				return
			}
		}
	}
	go forwardIO(os.Stdin, serverIn, []byte("\r\n"), []byte("\n"))
	go forwardIO(serverOut, os.Stdout, []byte("\n"), []byte("\r\n"))
}

func enableTrzsz(args *sshArgs, client *ssh.Client, session *ssh.Session, serverIn io.WriteCloser, serverOut io.Reader, tty bool) error {
	// not terminal or not tty
	if !isTerminal || !tty {
		wrapStdIO(serverIn, serverOut, tty)
		return nil
	}

	// disable trzsz ( trz / tsz )
	if strings.ToLower(getExOptionConfig(args, "EnableTrzsz")) == "no" {
		wrapStdIO(serverIn, serverOut, tty)
		onTerminalResize(func(width, height int) { _ = session.WindowChange(height, width) })
		return nil
	}

	// support trzsz ( trz / tsz )

	trzsz.SetAffectedByWindows(false)

	if args.Relay || isNoGUI() {
		// run as a relay
		trzszRelay := trzsz.NewTrzszRelay(os.Stdin, os.Stdout, serverIn, serverOut, trzsz.TrzszOptions{
			DetectTraceLog: args.TraceLog,
		})
		// reset terminal size on resize
		onTerminalResize(func(width, height int) { _ = session.WindowChange(height, width) })
		// setup tunnel connect
		trzszRelay.SetTunnelConnector(func(port int) net.Conn {
			conn, _ := dialWithTimeout(client, "tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
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
	trzszFilter := trzsz.NewTrzszFilter(os.Stdin, os.Stdout, serverIn, serverOut, trzsz.TrzszOptions{
		TerminalColumns: int32(width),
		DetectDragFile:  args.DragFile || strings.ToLower(getExOptionConfig(args, "EnableDragFile")) == "yes",
		DetectTraceLog:  args.TraceLog,
	})

	// reset terminal size on resize
	onTerminalResize(func(width, height int) {
		trzszFilter.SetTerminalColumns(int32(width))
		_ = session.WindowChange(height, width)
	})

	// setup default paths
	trzszFilter.SetDefaultUploadPath(userConfig.defaultUploadPath)
	trzszFilter.SetDefaultDownloadPath(userConfig.defaultDownloadPath)

	// setup tunnel connect
	trzszFilter.SetTunnelConnector(func(port int) net.Conn {
		conn, _ := dialWithTimeout(client, "tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		return conn
	})

	return nil
}

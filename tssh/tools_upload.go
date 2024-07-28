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
	"fmt"
	"net"
	"os"
	"time"

	"github.com/trzsz/trzsz-go/trzsz"
)

func execTrzUpload(args *sshArgs, ss *sshClientSession) int {
	if len(args.UploadFile.values) == 0 {
		return 0
	}

	wrapStdIO(nil, nil, ss.serverErr, ss.tty)
	trzsz.SetAffectedByWindows(false)
	width, _, err := getTerminalSize()
	if err == nil {
		width = 80
	}
	trzszFilter := trzsz.NewTrzszFilter(os.Stdin, os.Stdout, ss.serverIn, ss.serverOut, trzsz.TrzszOptions{
		TerminalColumns: int32(width),
		DetectTraceLog:  args.TraceLog,
		EnableZmodem:    true,
	})
	defer trzszFilter.ResetTerminal()
	onTerminalResize(func(width, height int) {
		trzszFilter.SetTerminalColumns(int32(width))
	})
	trzszFilter.SetProgressColorPair(userConfig.progressColorPair)
	trzszFilter.SetTunnelConnector(func(port int) net.Conn {
		conn, _ := ss.client.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		return conn
	})

	files := args.UploadFile.values
	errCh, err := trzszFilter.OneTimeUpload(files)
	if err != nil {
		warning("uplaod %v failed: %v", files, err)
		return 1
	}

	cmd := ss.cmd
	if cmd == "" {
		cmd = "trz -d"
	}
	if err := ss.session.Start(cmd); err != nil {
		warning("start command [%s] failed: %v", cmd, err)
		return 2
	}
	cleanupAfterLogin()
	_ = ss.session.Wait()

	if err := <-errCh; err != nil {
		warning("upload %v failed: %v", files, err)
		return 3
	}
	return 0
}

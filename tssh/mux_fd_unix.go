//go:build !windows

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
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// muxSendFd passes one file descriptor over a unix socket, the way OpenSSH's
// mm_send_fd does: a single SCM_RIGHTS control message with a one byte payload.
func muxSendFd(conn *net.UnixConn, fd int) error {
	_, _, err := conn.WriteMsgUnix([]byte{0}, unix.UnixRights(fd), nil)
	if err != nil {
		return fmt.Errorf("send fd failed: %w", err)
	}
	return nil
}

// muxRecvFd receives one file descriptor sent by muxSendFd or OpenSSH's mm_send_fd.
// The descriptor is close-on-exec and owned by the returned file.
func muxRecvFd(conn *net.UnixConn, name string) (*os.File, error) {
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	_, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		return nil, fmt.Errorf("receive fd failed: %w", err)
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, fmt.Errorf("parse fd control message failed: %w", err)
	}
	for i := range msgs {
		fds, err := unix.ParseUnixRights(&msgs[i])
		if err != nil || len(fds) == 0 {
			continue
		}
		for _, extra := range fds[1:] {
			_ = unix.Close(extra)
		}
		return os.NewFile(uintptr(fds[0]), name), nil
	}
	return nil, fmt.Errorf("no fd received")
}

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
	"os"

	"golang.org/x/sys/unix"
)

func isRemoteSshEnv(pid int) bool {
	for range 1000 {
		kinfo, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
		if err != nil {
			return false
		}

		name := kinfo.Proc.P_comm[:]
		idx := bytes.IndexByte(name, '\x00')
		if idx > 0 && bytes.Equal(name[:idx], []byte("sshd")) {
			return true
		}

		pid = int(kinfo.Eproc.Ppid)
		if pid == 0 {
			return false
		}
	}
	return false
}

func isDockerEnv() bool {
	if _, err := os.Stat("/.dockerenv"); !os.IsNotExist(err) {
		return true
	}
	return false
}

func isNoGUI() bool {
	if os.Getenv("DISPLAY") != "" {
		return false
	}
	return isDockerEnv() || isRemoteSshEnv(os.Getppid()) || isSshTmuxEnv()
}

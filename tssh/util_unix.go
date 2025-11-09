//go:build !windows && !darwin

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
	"os"
	"strconv"
)

func isRemoteSshEnv(pid int) bool {
	for range 1000 {
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			return false
		}

		idx := bytes.IndexByte(stat, '(')
		if idx < 0 {
			return false
		}
		stat = stat[idx+1:]
		idx = bytes.IndexByte(stat, ')')
		if idx < 0 {
			return false
		}

		if bytes.Equal(stat[:idx], []byte("sshd")) {
			return true
		}

		if len(stat) < 5 {
			return false
		}
		stat = stat[idx+4:]
		idx = bytes.IndexByte(stat, ' ')
		if idx < 1 {
			return false
		}

		pid, err = strconv.Atoi(string(stat[:idx]))
		if err != nil || pid == 0 {
			return false
		}
	}
	return false
}

func isDockerEnv() bool {
	if _, err := os.Stat("/.dockerenv"); !os.IsNotExist(err) {
		return true
	}
	cgroup, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return false
	}
	return bytes.Contains(cgroup, []byte(":/docker/"))
}

func isNoGUI() bool {
	if os.Getenv("DISPLAY") != "" {
		return false
	}
	return isDockerEnv() || isRemoteSshEnv(os.Getppid()) || isSshTmuxEnv()
}

func getIterm2Manager() terminalManager {
	return nil
}

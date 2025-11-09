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
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func isNoGUI() bool {
	pid := os.Getppid()
	for range 1000 {
		handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
		if err != nil {
			return false
		}
		defer windows.CloseHandle(handle)

		var path [windows.MAX_PATH]uint16
		var pathLen uint32 = uint32(len(path))
		err = windows.QueryFullProcessImageName(handle, 0, &path[0], &pathLen)
		if err != nil {
			return false
		}

		if strings.HasSuffix(windows.UTF16ToString(path[:pathLen]), "sshd.exe") {
			return true
		}

		pbi := windows.PROCESS_BASIC_INFORMATION{}
		if err := windows.NtQueryInformationProcess(handle, windows.ProcessBasicInformation,
			unsafe.Pointer(&pbi), uint32(unsafe.Sizeof(pbi)), nil); err != nil {
			return false
		}
		pid = int(pbi.InheritedFromUniqueProcessId)
	}
	return false
}

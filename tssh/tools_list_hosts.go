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
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
)

func execListHosts() (int, bool) {
	hosts := getAllHosts()

	if hosts == nil {
		hosts = []*sshHost{}
	}
	result, err := json.MarshalIndent(hosts, "", "  ")
	if err != nil {
		warning("json marshal indent failed: %v", err)
		return 1, true
	}

	hostsJson := string(result)
	if runtime.GOOS == "windows" {
		hostsJson = strings.ReplaceAll(hostsJson, "\n", "\r\n")
	}
	fmt.Println(hostsJson)

	return 0, true
}

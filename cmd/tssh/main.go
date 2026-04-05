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

package main

import (
	"os"
	"strings"

	"github.com/trzsz/trzsz-ssh/tssh"
)

func main() {
	argIdx := 1

	if len(os.Args) > 1 {
		// In Termux on Android, termux-exec may inject the absolute path of the
		// executable as the first argument (os.Args[1]) due to W^X restrictions.
		// We detect this by checking for termux-exec's specific environment variable
		// and verifying if the first argument points to the Termux file system.
		if exe := os.Getenv("TERMUX_EXEC__PROC_SELF_EXE"); exe != "" &&
			strings.HasPrefix(os.Args[1], "/data/data/com.termux/files/") {
			argIdx = 2
		}
	}

	os.Exit(tssh.TsshMain(os.Args[argIdx:]))
}

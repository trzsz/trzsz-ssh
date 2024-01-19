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
	"math"
	"os"
)

const (
	openTermDefault = 0
	openTermPane    = 1
	openTermTab     = 2
	openTermWindow  = 3
)

type terminalManager interface {
	openTerminals(keywords string, openType int, hosts []*sshHost)
}

func getTerminalManager() terminalManager {
	if mgr := getTmuxManager(); mgr != nil {
		return mgr
	}
	if mgr := getIterm2Manager(); mgr != nil {
		return mgr
	}
	if mgr := getWindowsTerminalManager(); mgr != nil {
		return mgr
	}
	debug("doesn't support multiple selections")
	return nil
}

type paneHost struct {
	alias  string
	paneId string
}

func getPanesMatrix(hosts []*sshHost) [][]*paneHost {
	rows := int(math.Floor(math.Sqrt(float64(len(hosts)))))
	cols := make([]int, rows)
	for i := 0; i < len(hosts); i++ {
		cols[i%rows]++
	}
	matrix := make([][]*paneHost, rows)
	idx := 0
	for i := 0; i < rows; i++ {
		matrix[i] = make([]*paneHost, cols[i])
		for j := 0; j < cols[i]; j++ {
			matrix[i][j] = &paneHost{hosts[idx].Alias, ""}
			idx++
		}
	}
	return matrix
}

func setTerminalTitle(title string) {
	fmt.Fprintf(os.Stderr, "\033]0;%s\007", title)
}

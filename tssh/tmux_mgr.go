/*
MIT License

Copyright (c) 2023 Lonny Wong <lonnywong@qq.com>

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
	"os/exec"
	"strconv"
	"strings"
)

type tmuxMgr struct {
}

func (m *tmuxMgr) openTerminals(openType int, hosts []*sshHost) {
	if len(hosts) < 2 {
		return
	}
	switch openType {
	case openTermWin, openTermTab:
		m.openWindows(hosts)
	case openTermPane:
		m.openPanes(hosts)
	}
}

func (m *tmuxMgr) openWindows(hosts []*sshHost) {
	if err := exec.Command("tmux", "renamew", hosts[0].Alias).Run(); err != nil {
		warning("Failed to rename tmux window: %v", err)
	} else {
		onExitFuncs = append(onExitFuncs, func() {
			_ = exec.Command("tmux", "setw", "automatic-rename").Run()
		})
	}
	for _, host := range hosts[1:] {
		if err := exec.Command("tmux", appendArgs(host.Alias, "neww", "-n", host.Alias)...).Run(); err != nil {
			warning("Failed to open tmux window: %v", err)
		}
	}
}

func (m *tmuxMgr) openPanes(hosts []*sshHost) {
	matrix := getPanesMatrix(hosts)
	out, err := exec.Command("tmux", "display", "-p", "#{pane_id}").Output()
	if err != nil {
		warning("Failed to get tmux pane id: %v", err)
		return
	}
	matrix[0][0].paneId = strings.TrimSpace(string(out))
	for i := len(matrix) - 1; i > 0; i-- {
		matrix[i][0].paneId = m.splitWindow(matrix[i][0].alias, "-v", matrix[0][0].paneId, strconv.Itoa(100/(i+1)))
	}
	for i := 0; i < len(matrix); i++ {
		for j := len(matrix[i]) - 1; j > 0; j-- {
			matrix[i][j].paneId = m.splitWindow(matrix[i][j].alias, "-h", matrix[i][0].paneId, strconv.Itoa(100/(j+1)))
		}
	}
	for i := 0; i < len(matrix); i++ {
		for j := 0; j < len(matrix[i]); j++ {
			if matrix[i][j].paneId != "" {
				_ = exec.Command("tmux", "selectp", "-t", matrix[i][j].paneId).Run()
			}
		}
	}
}

func (m *tmuxMgr) splitWindow(alias, axes, target, percentage string) string {
	if target == "" {
		return ""
	}
	out, err := exec.Command("tmux",
		appendArgs(alias, "splitw", axes, "-t", target, "-p", percentage, "-P", "-F", "#{pane_id}")...).Output()
	if err != nil {
		warning("Failed to split tmux window: %v", err)
		return ""
	}
	return strings.TrimSpace(string(out))
}

func getTmuxManager() terminalManager {
	if os.Getenv("TMUX") == "" {
		return nil
	}
	if !commandExists("tmux") {
		return nil
	}
	return &tmuxMgr{}
}

func commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

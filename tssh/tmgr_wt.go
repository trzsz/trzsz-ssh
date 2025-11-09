//go:build windows

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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type wtMgr struct {
	keywords string
}

func (m *wtMgr) openTerminals(keywords string, openType int, hosts []*sshHost) {
	if len(hosts) < 2 {
		return
	}
	m.keywords = keywords
	switch openType {
	case openTermDefault:
		if len(hosts) > 36 {
			m.openTabs(hosts)
		} else {
			m.openPanes(hosts)
		}
	case openTermPane:
		m.openPanes(hosts)
	case openTermTab:
		m.openTabs(hosts)
	case openTermWindow:
		m.openWindows(hosts)
	}
}

func (m *wtMgr) execWt(alias string, args ...string) error {
	cmdArgs := []string{"/c", "wt"}
	cmdArgs = append(cmdArgs, args...)
	cmdArgs = append(cmdArgs, "--title", alias)
	keywordsMatched := false
	for _, arg := range os.Args {
		if strings.Contains(arg, ";") {
			return fmt.Errorf("Windows Terminal does not support ';', use '|cat&&' instead.")
		}
		if m.keywords != "" && arg == m.keywords {
			if keywordsMatched {
				return fmt.Errorf("unable to handle duplicate keywords '%s'", m.keywords)
			}
			keywordsMatched = true
			cmdArgs = append(cmdArgs, alias)
			continue
		}
		cmdArgs = append(cmdArgs, arg)
	}
	if m.keywords == "" {
		cmdArgs = append(cmdArgs, alias)
	} else if !keywordsMatched {
		return fmt.Errorf("unable to handle replace keywords '%s'", m.keywords)
	}
	return exec.Command("cmd", cmdArgs...).Run()
}

func (m *wtMgr) openWindows(hosts []*sshHost) {
	setTerminalTitle(hosts[0].Alias)
	for _, host := range hosts[1:] {
		if err := m.execWt(host.Alias, "-w", "-1"); err != nil {
			warning("Failed to open wt window: %v", err)
			return
		}
	}
}

func (m *wtMgr) openTabs(hosts []*sshHost) {
	setTerminalTitle(hosts[0].Alias)
	for _, host := range hosts[1:] {
		if err := m.execWt(host.Alias, "-w", "0", "nt"); err != nil {
			warning("Failed to open wt tab: %v", err)
			return
		}
	}
}

func (m *wtMgr) openPanes(hosts []*sshHost) {
	setTerminalTitle(hosts[0].Alias)
	matrix := getPanesMatrix(hosts)
	for i := len(matrix) - 1; i > 0; i-- {
		percentage := "." + strconv.Itoa(100/(i+1))
		if err := m.execWt(matrix[i][0].alias, "-w", "0", "sp", "-H", "-s", percentage); err != nil {
			warning("Failed to split wt pane: %v", err)
			return
		}
		time.Sleep(100 * time.Millisecond) // wait for new pane focus
		if err := exec.Command("cmd", "/c", "wt", "-w", "0", "mf", "up").Run(); err != nil {
			warning("Failed to move wt focus: %v", err)
			return
		}
		time.Sleep(100 * time.Millisecond) // wait for new pane focus
	}
	for i := range matrix {
		if i > 0 {
			if err := exec.Command("cmd", "/c", "wt", "-w", "0", "mf", "down").Run(); err != nil {
				warning("Failed to move wt focus: %v", err)
				return
			}
			time.Sleep(100 * time.Millisecond) // wait for new pane focus
		}
		for j := 1; j < len(matrix[i]); j++ {
			percentage := "." + strconv.Itoa(100-100/(len(matrix[i])-j+1))
			if err := m.execWt(matrix[i][j].alias, "-w", "0", "sp", "-V", "-s", percentage); err != nil {
				warning("Failed to split wt pane: %v", err)
				return
			}
			time.Sleep(100 * time.Millisecond) // wait for new pane focus
		}
	}
}

func commandExists(exe string) bool {
	path := os.Getenv("Path")
	for p := range strings.SplitSeq(path, ";") {
		if isFileExist(filepath.Join(p, exe)) {
			return true
		}
	}
	return false
}

func getWindowsTerminalManager() terminalManager {
	if isNoGUI() {
		debug("no graphical user interface (GUI)")
		return nil
	}
	if !commandExists("wt.exe") {
		debug("no executable wt.exe")
		return nil
	}
	debug("running in windows terminal")
	return &wtMgr{}
}

func getTmuxManager() terminalManager {
	return nil
}

func getIterm2Manager() terminalManager {
	return nil
}

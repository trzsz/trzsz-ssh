//go:build !windows

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
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/alessio/shellescape"
)

type tmuxMgr struct {
	keywords     string
	majorVersion int
	minorVersion int
}

func (m *tmuxMgr) openTerminals(keywords string, openType int, hosts []*sshHost) {
	if len(hosts) < 2 {
		return
	}
	m.keywords = keywords
	switch openType {
	case openTermDefault:
		if len(hosts) > 36 {
			m.openWindows(hosts)
		} else {
			m.openPanes(hosts)
		}
	case openTermPane:
		m.openPanes(hosts)
	case openTermTab, openTermWindow:
		m.openWindows(hosts)
	}
}

func (m *tmuxMgr) appendArgs(alias string, args ...string) ([]string, error) {
	var cmdArgs []string
	keywordsMatched := false
	for _, arg := range os.Args {
		if m.keywords != "" && arg == m.keywords {
			if keywordsMatched {
				return nil, fmt.Errorf("unable to handle duplicate keywords '%s'", m.keywords)
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
		return nil, fmt.Errorf("unable to handle replace keywords '%s'", m.keywords)
	}
	return append(args, shellescape.QuoteCommand(cmdArgs)), nil
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
		args, err := m.appendArgs(host.Alias, "neww", "-n", host.Alias)
		if err != nil {
			warning("Failed to open tmux window: %v", err)
			return
		}
		if err := exec.Command("tmux", args...).Run(); err != nil {
			warning("Failed to open tmux window: %v", err)
			return
		}
	}
}

func (m *tmuxMgr) openPanes(hosts []*sshHost) {
	matrix := getPanesMatrix(hosts)
	out, err := exec.Command("tmux", "display", "-p", "#{pane_id}|#{pane_title}|#{version}").Output()
	if err != nil {
		warning("Failed to get tmux pane id and title: %v", err)
		return
	}
	output := strings.TrimSpace(string(out))
	tokens := strings.Split(output, "|")
	if len(tokens) > 2 && tokens[2] != "" {
		m.parseTmuxVersion(tokens[2])
	}
	matrix[0][0].paneId = tokens[0]
	for i := len(matrix) - 1; i > 0; i-- {
		matrix[i][0].paneId = m.splitWindow(matrix[i][0].alias, "-v", matrix[0][0].paneId, strconv.Itoa(100/(i+1)))
	}
	for i := 0; i < len(matrix); i++ {
		for j := len(matrix[i]) - 1; j > 0; j-- {
			matrix[i][j].paneId = m.splitWindow(matrix[i][j].alias, "-h", matrix[i][0].paneId, strconv.Itoa(100/(j+1)))
		}
	}
	// change panes title
	for i := 0; i < len(matrix); i++ {
		for j := 0; j < len(matrix[i]); j++ {
			if matrix[i][j].paneId != "" {
				_ = exec.Command("tmux", "selectp", "-t", matrix[i][j].paneId, "-T", matrix[i][j].alias).Run()
			}
		}
	}
	if len(tokens) > 1 && tokens[1] != "" {
		// reset pane title after exit
		onExitFuncs = append(onExitFuncs, func() {
			_ = exec.Command("tmux", "selectp", "-t", tokens[0], "-T", tokens[1]).Run()
		})
	}
	// reset panes order
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
	var err error
	var args []string
	if m.majorVersion > 3 || (m.majorVersion == 3 && m.minorVersion >= 1) {
		args, err = m.appendArgs(alias, "splitw", axes, "-t", target, "-l", percentage+"%", "-P", "-F", "#{pane_id}")
	} else {
		args, err = m.appendArgs(alias, "splitw", axes, "-t", target, "-p", percentage, "-P", "-F", "#{pane_id}")
	}
	if err != nil {
		warning("Failed to split tmux window: %v", err)
		return ""
	}
	out, err := exec.Command("tmux", args...).Output()
	if err != nil {
		warning("Failed to split tmux window: %v", err)
		return ""
	}
	return strings.TrimSpace(string(out))
}

func commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

func getTmuxManager() terminalManager {
	if os.Getenv("TMUX") == "" {
		debug("no TMUX environment variable")
		return nil
	}
	if !commandExists("tmux") {
		debug("no executable tmux")
		return nil
	}
	debug("running in tmux")
	return &tmuxMgr{}
}

func getWindowsTerminalManager() terminalManager {
	return nil
}

func (m *tmuxMgr) parseTmuxVersion(version string) {
	pos := strings.IndexByte(version, '.')
	if pos < 1 {
		return
	}
	if ver, err := strconv.Atoi(version[:pos]); err == nil {
		m.majorVersion = ver
	}
	subver := version[pos+1:]
	pos = len(subver)
	for i, c := range subver {
		if c >= '0' && c <= '9' {
			continue
		}
		pos = i
		break
	}
	if ver, err := strconv.Atoi(subver[:pos]); err == nil {
		m.minorVersion = ver
	}
}

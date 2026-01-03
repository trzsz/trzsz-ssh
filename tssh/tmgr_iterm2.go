//go:build darwin

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
	"os"
	"sync"

	"github.com/trzsz/iterm2"
	"github.com/trzsz/shellescape"
)

var initIterm2Once sync.Once

type iterm2Mgr struct {
	keywords string
}

func (m *iterm2Mgr) openTerminals(keywords string, openType int, hosts []*sshHost) {
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

func (m *iterm2Mgr) setTitle(session *iterm2.Session, alias string) {
	_ = session.Inject(fmt.Appendf(nil, "\033]0;%s\007", alias))
}

func (m *iterm2Mgr) execCmd(session *iterm2.Session, alias string) error {
	var cmdArgs []string
	keywordsMatched := false
	for _, arg := range os.Args {
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
	cmd := shellescape.QuoteCommand(cmdArgs)
	if err := session.SendText(fmt.Sprintf("%s\n", cmd)); err != nil {
		return fmt.Errorf("iTerm2 send text failed: %v", err)
	}
	return nil
}

func (m *iterm2Mgr) openWindows(hosts []*sshHost) {
	m.setTitle(iterm2Session, hosts[0].Alias)
	for _, host := range hosts[1:] {
		_, session, err := iterm2Session.GetApp().CreateWindow()
		if err != nil {
			warning("iTerm2 create window failed: %v", err)
			return
		}
		m.setTitle(session, host.Alias)
		if err := m.execCmd(session, host.Alias); err != nil {
			warning("iTerm2 execute command failed: %v", err)
			return
		}
	}
}

func (m *iterm2Mgr) openTabs(hosts []*sshHost) {
	window := iterm2Session.GetWindow()
	m.setTitle(iterm2Session, hosts[0].Alias)
	for _, host := range hosts[1:] {
		_, session, err := window.CreateTab()
		if err != nil {
			warning("iTerm2 create tab failed: %v", err)
			return
		}
		m.setTitle(session, host.Alias)
		if err := m.execCmd(session, host.Alias); err != nil {
			warning("iTerm2 execute command failed: %v", err)
			return
		}
	}
}

func (m *iterm2Mgr) openPanes(hosts []*sshHost) {
	m.setTitle(iterm2Session, hosts[0].Alias)
	matrix := getPanesMatrix(hosts)
	sessions := make([]*iterm2.Session, len(matrix))
	sessions[0] = iterm2Session
	for i := len(matrix) - 1; i > 0; i-- {
		pane, err := iterm2Session.SplitPane(iterm2.SplitPaneOptions{Vertical: false})
		if err != nil {
			warning("iTerm2 split pane failed: %v", err)
			return
		}
		sessions[i] = pane
		m.setTitle(pane, matrix[i][0].alias)
		if err := m.execCmd(pane, matrix[i][0].alias); err != nil {
			warning("iTerm2 execute command failed: %v", err)
			return
		}
	}
	for i := range matrix {
		session := sessions[i]
		if session == nil {
			continue
		}
		for j := len(matrix[i]) - 1; j > 0; j-- {
			pane, err := session.SplitPane(iterm2.SplitPaneOptions{Vertical: true})
			if err != nil {
				warning("iTerm2 split pane failed: %v", err)
				return
			}
			m.setTitle(pane, matrix[i][j].alias)
			if err := m.execCmd(pane, matrix[i][j].alias); err != nil {
				warning("iTerm2 execute command failed: %v", err)
				return
			}
		}
	}
}

func getIterm2Manager() terminalManager {
	initIterm2Session()
	if iterm2Session == nil {
		return nil
	}
	return &iterm2Mgr{}
}

func initIterm2Session() {
	initIterm2Once.Do(func() {
		if os.Getenv("TMUX") != "" {
			debug("running in tmux")
			return
		}

		if os.Getenv("ITERM_SESSION_ID") == "" {
			return
		}
		debug("running in iTerm2")

		app, err := iterm2.NewApp("tssh")
		if err != nil {
			debug("new iTerm2 app failed: %v", err)
			return
		}
		addOnExitFunc(func() { _ = app.Close() })

		iterm2Session, err = app.GetCurrentHostSession()
		if err != nil {
			debug("get iTerm2 host session failed: %v", err)
		}
	})
}

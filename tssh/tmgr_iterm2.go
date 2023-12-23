//go:build darwin

/*
MIT License

Copyright (c) 2023 Lonny Wong <lonnywong@qq.com>
Copyright (c) 2023 [Contributors](https://github.com/trzsz/trzsz-ssh/graphs/contributors)

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
	"strings"

	"github.com/alessio/shellescape"
	"github.com/trzsz/iterm2"
)

type iterm2Mgr struct {
	app iterm2.App
}

func (m *iterm2Mgr) openTerminals(openType int, hosts []*sshHost) {
	if len(hosts) < 2 {
		return
	}
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

func (m *iterm2Mgr) setTitle(session iterm2.Session, alias string) {
	_ = session.Inject([]byte(fmt.Sprintf("\033]0;%s\007", alias)))
}

func (m *iterm2Mgr) execCmd(session iterm2.Session, alias string) {
	cmd := shellescape.QuoteCommand(append(os.Args, alias))
	if err := session.SendText(fmt.Sprintf("%s\n", cmd)); err != nil {
		warning("Failed to send text: %v", err)
	}
}

func (m *iterm2Mgr) getCurrentWindowSession() (iterm2.Window, iterm2.Session) {
	sessionID := os.Getenv("ITERM_SESSION_ID")
	windows, err := m.app.ListWindows()
	if err != nil {
		warning("Failed to create window: %v", err)
		return nil, nil
	}
	for _, window := range windows {
		tabs, err := window.ListTabs()
		if err != nil {
			warning("Failed to list tabs: %v", err)
			return nil, nil
		}
		for _, tab := range tabs {
			sessions, err := tab.ListSessions()
			if err != nil {
				warning("Failed to list sessions: %v", err)
				return nil, nil
			}
			for _, session := range sessions {
				if strings.Contains(sessionID, session.GetSessionID()) {
					return window, session
				}
			}
		}
	}
	warning("No current session: %s", sessionID)
	return nil, nil
}

func (m *iterm2Mgr) openWindows(hosts []*sshHost) {
	if _, session := m.getCurrentWindowSession(); session != nil {
		m.setTitle(session, hosts[0].Alias)
	}
	for _, host := range hosts[1:] {
		window, err := m.app.CreateWindow()
		if err != nil {
			warning("Failed to create window: %v", err)
			continue
		}
		tabs, err := window.ListTabs()
		if err != nil || len(tabs) == 0 {
			warning("Failed to list tabs: %v", err)
			continue
		}
		sessions, err := tabs[0].ListSessions()
		if err != nil || len(sessions) == 0 {
			warning("Failed to list sessions: %v", err)
			continue
		}
		m.setTitle(sessions[0], host.Alias)
		m.execCmd(sessions[0], host.Alias)
	}
}

func (m *iterm2Mgr) openTabs(hosts []*sshHost) {
	window, session := m.getCurrentWindowSession()
	if window == nil {
		return
	}
	if session != nil {
		m.setTitle(session, hosts[0].Alias)
	}
	for _, host := range hosts[1:] {
		tab, err := window.CreateTab()
		if err != nil {
			warning("Failed to create tab: %v", err)
			continue
		}
		sessions, err := tab.ListSessions()
		if err != nil || len(sessions) == 0 {
			warning("Failed to list sessions: %v", err)
			continue
		}
		m.setTitle(sessions[0], host.Alias)
		m.execCmd(sessions[0], host.Alias)
	}
}

func (m *iterm2Mgr) openPanes(hosts []*sshHost) {
	_, session := m.getCurrentWindowSession()
	if session == nil {
		return
	}
	m.setTitle(session, hosts[0].Alias)
	matrix := getPanesMatrix(hosts)
	sessions := make([]iterm2.Session, len(matrix))
	sessions[0] = session
	for i := len(matrix) - 1; i > 0; i-- {
		pane, err := session.SplitPane(iterm2.SplitPaneOptions{Vertical: false})
		if err != nil {
			warning("Failed to split pane: %v", err)
			continue
		}
		sessions[i] = pane
		m.setTitle(pane, matrix[i][0].alias)
		m.execCmd(pane, matrix[i][0].alias)
	}
	for i := 0; i < len(matrix); i++ {
		session := sessions[i]
		if session == nil {
			continue
		}
		for j := len(matrix[i]) - 1; j > 0; j-- {
			pane, err := session.SplitPane(iterm2.SplitPaneOptions{Vertical: true})
			if err != nil {
				warning("Failed to split pane: %v", err)
				continue
			}
			m.setTitle(pane, matrix[i][j].alias)
			m.execCmd(pane, matrix[i][j].alias)
		}
	}
}

func getIterm2Manager() terminalManager {
	if os.Getenv("ITERM_SESSION_ID") == "" {
		debug("no ITERM_SESSION_ID environment variable")
		return nil
	}
	app, err := iterm2.NewApp("tssh")
	if err != nil {
		debug("new iTerm2 app failed: %v", err)
		return nil
	}
	cleanupAfterLogined = append(cleanupAfterLogined, func() {
		app.Close()
	})
	debug("running in iTerm2")
	return &iterm2Mgr{app}
}

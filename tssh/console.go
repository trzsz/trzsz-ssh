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
	"io"
	"os"
	"runtime"
	"strings"
	"sync/atomic"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

type menuItem struct {
	key    string
	label  string
	action func() (tea.Model, tea.Cmd)
}

type menuModel struct {
	items           []*menuItem
	cursor          int
	menuWidth       int
	screenWidth     int
	quitting        bool
	backgroundStyle lipgloss.Style
	titleStyle      lipgloss.Style
	footerStyle     lipgloss.Style
	blankLineStyle  lipgloss.Style
	separatorStyle  lipgloss.Style
	activeItemStyle lipgloss.Style
	normalItemStyle lipgloss.Style
	activeBarStyle  lipgloss.Style
}

func initMenuModel(menuWidth, screenWidth int) *menuModel {
	bgColor := lipgloss.Color("#1b1b32")
	titleColor := lipgloss.Color("#A6E3A1")
	footerColor := lipgloss.Color("#6C7086")
	itemNormalFG := lipgloss.Color("#CDD6F4")
	itemSelectedFG := lipgloss.Color("#FFFCE1")
	itemSelectedBG := lipgloss.Color("#433C7C")
	separatorColor := lipgloss.Color("#31354A")
	highlightBarColor := lipgloss.Color("#FFD700")
	return &menuModel{
		cursor:          0,
		menuWidth:       menuWidth,
		screenWidth:     screenWidth,
		backgroundStyle: lipgloss.NewStyle().Background(bgColor).Width(screenWidth).Align(lipgloss.Center),
		titleStyle:      lipgloss.NewStyle().Foreground(titleColor).Background(bgColor).Bold(true).Width(menuWidth).Align(lipgloss.Center),
		footerStyle:     lipgloss.NewStyle().Foreground(footerColor).Background(bgColor).Width(menuWidth).Align(lipgloss.Center),
		blankLineStyle:  lipgloss.NewStyle().Background(bgColor).Width(menuWidth),
		separatorStyle:  lipgloss.NewStyle().Foreground(separatorColor).Background(bgColor).Width(menuWidth),
		activeItemStyle: lipgloss.NewStyle().Foreground(itemSelectedFG).Background(itemSelectedBG),
		normalItemStyle: lipgloss.NewStyle().Foreground(itemNormalFG).Background(bgColor),
		activeBarStyle:  lipgloss.NewStyle().Foreground(highlightBarColor).Background(itemSelectedBG),
	}
}

func (m *menuModel) Init() tea.Cmd {
	return nil
}

func (m *menuModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch s := msg.String(); s {
		case "ctrl+c", "esc", "q":
			m.quitting = true
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.items)-1 {
				m.cursor++
			}
		case "enter":
			if m.cursor >= 0 && m.cursor < len(m.items) {
				return m.items[m.cursor].action()
			}
			return m, nil
		default:
			for i, item := range m.items {
				if s == item.key {
					m.cursor = i
					return item.action()
				}
			}
		}
	}
	return m, nil
}

func (m *menuModel) View() string {
	if m.quitting {
		return ""
	}
	var builder strings.Builder
	m.writeLine(&builder, m.renderBlankLine())
	m.writeLine(&builder, m.titleStyle.Render(getText("console/title")))
	m.writeLine(&builder, m.renderBlankLine())
	m.writeLine(&builder, m.renderSeparator())
	m.renderMenuItems(&builder)
	m.writeLine(&builder, m.footerStyle.Render(getText("console/notes")))
	builder.WriteString(m.backgroundStyle.Render(m.renderBlankLine()))
	return builder.String()
}

func (m *menuModel) renderMenuItems(builder *strings.Builder) {
	var linePrefix string
	var textStyle lipgloss.Style
	for i, item := range m.items {
		if i == m.cursor {
			linePrefix, textStyle = m.activeBarStyle.Render("│ "), m.activeItemStyle
		} else {
			linePrefix, textStyle = m.normalItemStyle.Render("  "), m.normalItemStyle
		}
		blankLine := linePrefix + textStyle.Render(strings.Repeat(" ", m.menuWidth-2))
		m.writeLine(builder, blankLine)
		m.writeLine(builder, linePrefix+textStyle.Width(m.menuWidth-2).Render(item.label))
		m.writeLine(builder, blankLine)
		m.writeLine(builder, m.renderSeparator())
	}
}

func (m *menuModel) writeLine(builder *strings.Builder, line string) {
	if ansi.StringWidth(line) >= m.menuWidth {
		line = ansi.Truncate(line, m.menuWidth-1, "")
	}
	builder.WriteString(m.backgroundStyle.Render(line))
	builder.WriteByte('\n')
}

func (m *menuModel) renderBlankLine() string {
	return m.blankLineStyle.Render(strings.Repeat(" ", m.menuWidth))
}

func (m *menuModel) renderSeparator() string {
	return m.separatorStyle.Render(strings.Repeat("─", m.menuWidth))
}

func runConsole(escapeChar byte, writer io.WriteCloser, sshConn *sshConnection) {
	width := sshConn.session.GetTerminalWidth()
	model := initMenuModel(min(width, 60), width)

	var key, char string
	if escapeChar <= 26 {
		key = "ctrl+" + string([]byte{'a' - 1 + escapeChar})
		char = "^" + string([]byte{'A' - 1 + escapeChar})
	} else {
		key = string(escapeChar)
		char = string(escapeChar)
	}
	model.items = []*menuItem{
		{key, strings.ReplaceAll(getText("console/send_char"), "{0}", char), func() (tea.Model, tea.Cmd) {
			_, _ = writer.Write([]byte{escapeChar})
			model.quitting = true
			return model, tea.Quit
		}},
	}

	if runtime.GOOS != "windows" {
		var suspend bool
		defer func() {
			if suspend {
				go suspendProcess()
			}
		}()
		model.items = append(model.items, &menuItem{"ctrl+z", getText("console/suspend"), func() (tea.Model, tea.Cmd) {
			suspend = true
			model.quitting = true
			return model, tea.Quit
		}})
	}

	quitted := make(chan struct{})
	defer close(quitted)
	var exiting atomic.Bool
	model.items = append(model.items, &menuItem{".", getText("console/terminate"), func() (tea.Model, tea.Cmd) {
		exiting.Store(true)
		go func() {
			<-quitted
			sshConn.forceExit(kExitCodeConsoleKill, fmt.Sprintf("Exit due to user actions in the console or entered the ssh escape sequences ( %s. )", char))
		}()
		model.quitting = true
		return model, tea.Quit
	}})

	teaInput, cancelReader := newTeaStdinInput(func(buf []byte) {
		if enableDebugLogging {
			if ch := stdinInputChan.Load(); ch != nil {
				*ch <- append([]byte(nil), buf...)
				return
			}
		}
		_, _ = writer.Write(buf)
	})
	defer cancelReader()

	p := tea.NewProgram(model, teaInput, tea.WithOutput(os.Stderr))
	if _, err := p.Run(); err != nil {
		warning("run escape console failed: %v", err)
	}

	if !exiting.Load() {
		sshConn.session.RedrawScreen()
	}
}

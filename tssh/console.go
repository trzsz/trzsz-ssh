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
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/mattn/go-isatty"
)

type menuItem struct {
	label  string
	action func() (tea.Model, tea.Cmd)
}

type menuModel struct {
	items            []*menuItem
	cursor           int
	menuWidth        int
	screenWidth      int
	quitting         bool
	backgroundStyle  lipgloss.Style
	titleStyle       lipgloss.Style
	footerStyle      lipgloss.Style
	blankLineStyle   lipgloss.Style
	separatorStyle   lipgloss.Style
	activeItemStyle  lipgloss.Style
	normalItemStyle  lipgloss.Style
	activeBarStyle   lipgloss.Style
	inactiveBarStyle lipgloss.Style
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
		cursor:           0,
		menuWidth:        menuWidth,
		screenWidth:      screenWidth,
		backgroundStyle:  lipgloss.NewStyle().Background(bgColor).Width(screenWidth).Align(lipgloss.Center),
		titleStyle:       lipgloss.NewStyle().Foreground(titleColor).Background(bgColor).Bold(true).Width(menuWidth).Align(lipgloss.Center),
		footerStyle:      lipgloss.NewStyle().Foreground(footerColor).Background(bgColor).Width(menuWidth).Align(lipgloss.Center),
		blankLineStyle:   lipgloss.NewStyle().Background(bgColor).Width(menuWidth),
		separatorStyle:   lipgloss.NewStyle().Foreground(separatorColor).Background(bgColor).Width(menuWidth),
		activeItemStyle:  lipgloss.NewStyle().Foreground(itemSelectedFG).Background(itemSelectedBG).Width(menuWidth - 1),
		normalItemStyle:  lipgloss.NewStyle().Foreground(itemNormalFG).Background(bgColor).Width(menuWidth - 1),
		activeBarStyle:   lipgloss.NewStyle().Foreground(highlightBarColor).Background(itemSelectedBG),
		inactiveBarStyle: lipgloss.NewStyle().Foreground(bgColor).Background(bgColor),
	}
}

func (m *menuModel) Init() tea.Cmd {
	return nil
}

func (m *menuModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
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
	for i, item := range m.items {
		barStyle, textStyle := m.inactiveBarStyle, m.normalItemStyle
		if i == m.cursor {
			barStyle, textStyle = m.activeBarStyle, m.activeItemStyle
		}
		prefix := barStyle.Render("│")
		blankLine := prefix + textStyle.Render(strings.Repeat(" ", m.menuWidth-1))
		m.writeLine(builder, blankLine)
		m.writeLine(builder, prefix+textStyle.Render(" "+getText(item.label)))
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

func suspendProcess() {
	conCh := make(chan os.Signal, 1)
	signal.Notify(conCh, syscall.SIGCONT)
	defer func() { signal.Stop(conCh); close(conCh) }()

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGSTOP); err != nil {
		warning("suspend current process failed: %v", err)
		return
	}

	debug("current process is suspended")
	for range conCh {
		if isatty.IsTerminal(os.Stdin.Fd()) {
			debug("current process is running in foreground")
			_, _ = makeStdinRaw()
			return
		}
		debug("current process is running in background")
	}
}

func killProcess(ss *sshClientSession) {
	go func() {
		time.Sleep(500 * time.Millisecond)
		debug("force exit due to normal exit timeout")
		_, _ = doWithTimeout(func() (int, error) { cleanupOnClose(); return 0, nil }, 50*time.Millisecond)
		_, _ = doWithTimeout(func() (int, error) { cleanupOnExit(); return 0, nil }, 300*time.Millisecond)
		os.Exit(kExitCodeConsoleKill)
	}()
	ss.Close()
}

func runConsole(reader io.Reader, writer io.WriteCloser, ss *sshClientSession) {
	width := ss.session.GetTerminalWidth()
	model := initMenuModel(min(width, 60), width)
	model.items = []*menuItem{
		{"console/send~", func() (tea.Model, tea.Cmd) {
			_, _ = writer.Write([]byte{'~'})
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
		model.items = append(model.items, &menuItem{
			"console/suspend", func() (tea.Model, tea.Cmd) {
				suspend = true
				model.quitting = true
				return model, tea.Quit
			}})
	}

	model.items = append(model.items, &menuItem{
		"console/terminate", func() (tea.Model, tea.Cmd) {
			go killProcess(ss)
			model.quitting = true
			return model, tea.Quit
		}})

	p := tea.NewProgram(model, tea.WithInput(reader), tea.WithOutput(os.Stderr))
	if _, err := p.Run(); err != nil {
		warning("run escape console failed: %v", err)
	}
	ss.session.RedrawScreen()
}

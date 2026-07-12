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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/mattn/go-runewidth"
	"github.com/trzsz/tsshd/tsshd"
)

var udpAttachSessionID uint64

var errAttachSessionSelection = errors.New("attach session selection failed")

var errAttachTsshdTooOld = errors.New("tsshd is too old and does not support the attach feature")

type previewResultMsg struct {
	idx     int
	content string
}

type previewRequest struct {
	idx    int
	viewID string
	result chan *previewResultMsg
}

type attachModel struct {
	tsshd      string
	client     SshClient
	items      []tsshd.ServerItem
	infos      []*tsshd.BaseInfo
	cursor     int
	offset     int
	chosen     int
	preview    string
	quitting   bool
	boxWidth   int
	boxHeight  int
	footer     string
	boxStyle   lipgloss.Style
	titleStyle lipgloss.Style
	curStyle   lipgloss.Style
	lineStyle  lipgloss.Style
	previewMu  sync.Mutex
	previewReq chan *previewRequest
	doneCh     chan struct{}
}

func (m *attachModel) Init() tea.Cmd {
	m.preview = "Loading..."
	m.boxStyle = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#7D56F4"))
	m.titleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#7D56F4")).MarginBottom(1)
	m.curStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#7D56F4")).Bold(true)
	m.lineStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFF"))
	m.footer = lipgloss.NewStyle().MarginTop(1).Render(
		"  Navigate : ↑/↓ · j/k · Tab/Shift+Tab    Select : Enter    Quit : q · Ctrl+C",
	)

	go func() {
		for {
			select {
			case req, ok := <-m.previewReq:
				if !ok {
					return
				}

				output, err := execTsshdCommand(m.client, m.tsshd, fmt.Sprintf(" --view %s", req.viewID))

				var content string
				if err != nil {
					content = fmt.Sprintf("ERROR: %v", err)
				} else {
					content = string(output)
				}

				req.result <- &previewResultMsg{idx: req.idx, content: content}

				close(req.result)

			case <-m.doneCh:
				return
			}
		}
	}()

	return tea.Batch(doTick(), m.fetchPreviewCmd(m.cursor))
}

func doTick() tea.Cmd {
	return tea.Tick(1*time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m *attachModel) fetchPreviewCmd(idx int) tea.Cmd {
	return func() tea.Msg {
		if idx == 0 {
			return previewResultMsg{idx: idx, content: "✨ Starting a brand new session..."}
		}

		item, info := m.items[idx-1], m.infos[idx-1]
		if info == nil {
			return previewResultMsg{idx: idx, content: item.Info}
		}
		if len(info.Sessions) == 0 {
			return previewResultMsg{idx: idx, content: "<< NO SESSION >>"}
		}

		m.previewMu.Lock()

		select {
		case req := <-m.previewReq: // discard old request
			req.result <- nil
			close(req.result)
		default:
		}

		req := &previewRequest{
			idx:    idx,
			viewID: fmt.Sprintf("%d.%d", item.Pid, info.Sessions[0].ID),
			result: make(chan *previewResultMsg, 1),
		}

		select {
		case <-m.doneCh:
			m.previewMu.Unlock()
			return nil
		case m.previewReq <- req:
		}

		m.previewMu.Unlock()

		select {
		case <-m.doneCh:
			return nil
		case msg := <-req.result:
			if msg == nil {
				return nil
			}
			return *msg
		}
	}
}

func (m *attachModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		const footerHeight = 2
		m.boxHeight = msg.Height - footerHeight - 2
		m.boxWidth = (msg.Width / 2) - 2
		m.boxStyle = m.boxStyle.Width(m.boxWidth).Height(m.boxHeight)
		return m, nil

	case tickMsg:
		return m, tea.Batch(doTick(), m.fetchPreviewCmd(m.cursor))

	case previewResultMsg:
		if msg.idx == m.cursor {
			m.preview = msg.content
		}
		return m, nil

	case tea.KeyPressMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			m.chosen = -1
			m.quitting = true
			return m, tea.Quit
		case "up", "k", "shift+tab":
			if m.cursor > 0 {
				m.cursor--
			} else {
				m.cursor = len(m.items)
			}
			m.preview = "Loading..."
			return m, m.fetchPreviewCmd(m.cursor)
		case "down", "j", "tab":
			if m.cursor < len(m.items) {
				m.cursor++
			} else {
				m.cursor = 0
			}
			m.preview = "Loading..."
			return m, m.fetchPreviewCmd(m.cursor)
		case "enter":
			m.chosen = m.cursor
			m.quitting = true
			return m, tea.Quit
		}
	}

	return m, nil
}

func (m *attachModel) View() tea.View {
	if m.quitting {
		return tea.NewView("")
	}

	if m.boxWidth == 0 || m.boxHeight == 0 {
		v := tea.NewView("Initializing...")
		v.AltScreen = true
		return v
	}

	if m.boxHeight < 5 || m.boxWidth < 10 {
		v := tea.NewView("Terminal window too small")
		v.AltScreen = true
		return v
	}

	leftLines := []string{m.titleStyle.Render(" Sessions ")}

	listAvailableHeight := m.boxHeight - 4
	if m.cursor < m.offset {
		m.offset = m.cursor
	} else if m.cursor >= m.offset+listAvailableHeight {
		m.offset = m.cursor - listAvailableHeight + 1
	}

	totalItems := len(m.items) + 1 // +1 for "New Session"
	for i := m.offset; i < m.offset+listAvailableHeight && i < totalItems; i++ {
		cursorStr := "  "
		if m.cursor == i {
			cursorStr = "▶ "
		}

		var row string
		if i == 0 {
			row = "✨ [Create a new session]"
		} else {
			idx := i - 1
			item := m.items[idx]
			info := m.infos[idx]

			name, title, startTime := "-", "-", "-"
			if info != nil {
				if info.Name != "" {
					name = info.Name
				}
				if info.Time > 0 {
					startTime = time.Unix(info.Time, 0).Local().Format("2006-01-02 15:04")
				}
				if len(info.Sessions) > 0 && info.Sessions[0].Title != "" {
					title = info.Sessions[0].Title
				}
			}

			row = fmt.Sprintf("💻 %s | Name: %s | Title: %s | StartTime: %s", strconv.Itoa(item.Pid), name, title, startTime)
		}

		row = clipString(cursorStr+row, m.boxWidth-2)
		if m.cursor == i {
			leftLines = append(leftLines, m.curStyle.Render(row))
		} else {
			leftLines = append(leftLines, m.lineStyle.Render(row))
		}
	}
	leftStr := m.boxStyle.Render(strings.Join(leftLines, "\n"))

	var rightView strings.Builder
	rightView.WriteString(m.titleStyle.Render(" Preview "))
	rightView.WriteString("\n")

	clippedPreview := clipText(m.preview, m.boxWidth-2, m.boxHeight-4)
	rightView.WriteString(clippedPreview)

	rightStr := m.boxStyle.Render(rightView.String())

	mainContent := lipgloss.JoinHorizontal(lipgloss.Top, leftStr, rightStr)

	content := lipgloss.JoinVertical(lipgloss.Left, mainContent, m.footer)

	v := tea.NewView(content)
	v.AltScreen = true
	return v
}

func clipString(s string, maxW int) string {
	if maxW <= 0 {
		return ""
	}
	if runewidth.StringWidth(s) <= maxW {
		return s
	}
	if maxW == 1 {
		return "…"
	}

	return runewidth.Truncate(s, maxW-1, "") + "…"
}

func clipText(text string, maxW, maxH int) string {
	if maxW <= 0 || maxH <= 0 {
		return ""
	}

	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	if len(lines) > maxH {
		lines = lines[:maxH]
	}

	for i, line := range lines {
		if runewidth.StringWidth(line) > maxW {
			lines[i] = runewidth.Truncate(line, maxW, "")
		}
	}

	return strings.Join(lines, "\n")
}

func attachToSession(tcpClient SshClient, tsshdPath, sessionName string) (*strings.Builder, error) {
	listOutput, err := execTsshdCommand(tcpClient, tsshdPath, " --list")
	if err != nil {
		return nil, err
	}
	if len(listOutput) == 0 {
		return nil, fmt.Errorf("tsshd list output is empty")
	}
	if bytes.HasPrefix(listOutput, []byte("\a{\"")) {
		return nil, errAttachTsshdTooOld
	}

	var items []tsshd.ServerItem
	if err := json.Unmarshal(listOutput, &items); err != nil {
		return nil, fmt.Errorf("tsshd list failed: %s", string(listOutput))
	}

	infos := make([]*tsshd.BaseInfo, len(items))
	for i, item := range items {
		var info tsshd.BaseInfo
		if err := json.Unmarshal([]byte(item.Info), &info); err == nil {
			infos[i] = &info
		}
	}

	if sessionName != "" {
		for i, info := range infos {
			if info != nil && info.Name == sessionName {
				return getAttachCommand(tsshdPath, items[i].Pid, info), nil
			}
		}
		for i, info := range infos {
			if info == nil {
				warning("get info of tsshd process [%d] failed: %v", items[i].Pid, items[i].Info)
			}
		}
		return nil, nil
	}

	if !isTerminal {
		return nil, fmt.Errorf("not a terminal")
	}

	model := &attachModel{
		tsshd:      tsshdPath,
		client:     tcpClient,
		items:      items,
		infos:      infos,
		previewReq: make(chan *previewRequest, 1),
		doneCh:     make(chan struct{}),
	}

	defer func() { close(model.doneCh) }()

	p := tea.NewProgram(model)
	if _, err := p.Run(); err != nil {
		return nil, fmt.Errorf("%w: %v", errAttachSessionSelection, err)
	}

	if model.chosen < 0 {
		return nil, fmt.Errorf("%w: canceled by user", errAttachSessionSelection)
	}
	if model.chosen == 0 {
		return nil, nil
	}
	idx := model.chosen - 1
	return getAttachCommand(tsshdPath, items[idx].Pid, infos[idx]), nil
}

func getAttachCommand(tsshdPath string, pid int, info *tsshd.BaseInfo) *strings.Builder {
	if info != nil && len(info.Sessions) > 0 {
		udpAttachSessionID = info.Sessions[0].ID
	}
	var buf strings.Builder
	buf.WriteString(tsshdPath)
	buf.WriteString(" --attach ")
	buf.WriteString(strconv.Itoa(pid))
	return &buf
}

func execTsshdCommand(client SshClient, tsshdPath, tsshdCmd string) ([]byte, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("new session for tsshd command failed: %v", err)
	}
	defer func() { _ = session.Close() }()

	cmd := tsshdPath + tsshdCmd
	output, err := session.CombinedOutput(cmd)
	if err != nil {
		return nil, fmt.Errorf("session exec command [%s] failed: %v", cmd, err)
	}

	return bytes.TrimSpace(output), nil
}

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
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

func showConnectionLostNotif(client *sshUdpClient) {
	tmux := isRunningTmuxIntegration()
	client.notifInterceptor.tmuxFlag.Store(tmux)
	client.notifInterceptor.cursorPos.Store(nil)

	client.debug("start intercepting user input")
	intCh := client.notifInterceptor.interceptInput()
	defer func() {
		client.debug("releasing intercepted user input")
		client.notifInterceptor.cancelIntercept()
	}()
	go interactWithUserInput(client, intCh)

	tmuxPaneId, tmuxColumns := "", 0
	if tmux {
		tmuxPaneId, tmuxColumns = initTmuxNotifPaneId(client)
	} else if client.notifInterceptor.noticeOnTop {
		initCursorPosition(client)
	}
	if !client.isReconnectTimeout() {
		return
	}

	notif := newNotifModel(client, tmuxPaneId, tmuxColumns)
	client.notifModel.Store(notif)
	defer client.notifModel.Store(nil)

	for client.isReconnectTimeout() {
		notif.renderView(false, false)
		time.Sleep(200 * time.Millisecond)
	}
	notif.renderView(false, true)
	_, _ = doWithTimeout(func() (int, error) {
		client.debug("requesting screen redraw")
		client.sshConn.session.RedrawScreen()
		client.debug("screen redraw completed")
		return 0, nil
	}, client.reconnectTimeout)
	notif.renderView(false, false)
}

func interactWithUserInput(client *sshUdpClient, intCh <-chan byte) {
	for client.isReconnectTimeout() {
		select {
		case ch, ok := <-intCh:
			client.debug("discard user input %s", strconv.QuoteToASCII(string(ch)))
			if !ok {
				return
			}
			switch ch {
			case '\x01': // ctrl + a
				client.notifInterceptor.showFullNotif.Store(!client.notifInterceptor.showFullNotif.Load())
			case '\x03': // ctrl + c
				client.exit(kExitCodeUdpCtrlC, "Exit due to connection was lost and Ctrl+C was pressed")
				return
			}
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func initTmuxNotifPaneId(client *sshUdpClient) (string, int) {
	client.notifInterceptor.tmuxPaneId.Store(nil)
	paneId, columns := getTmuxPaneIdAndColumns()
	if paneId != "" && columns > 0 {
		tmuxDebug("obtained tmux pane id [%s] and columns [%d] from iTerm2 API", paneId, columns)
		client.notifInterceptor.tmuxPaneId.Store(&paneId)
		return paneId, columns
	}

	for client.isReconnectTimeout() {
		time.Sleep(100 * time.Millisecond)
		paneId := client.notifInterceptor.tmuxPaneId.Load()
		if paneId != nil {
			tmuxDebug("obtained tmux pane id [%s] and columns [%d] from stdin", *paneId, columns)
			return *paneId, 0
		}
	}

	tmuxDebug("reconnected successfully without obtaining tmux pane id and columns")
	return "", 0
}

func initCursorPosition(client *sshUdpClient) {
	_, _ = os.Stderr.WriteString(ansi.RequestCursorPositionReport)
	for range 50 {
		time.Sleep(10 * time.Millisecond)
		if client.notifInterceptor.cursorPos.Load() != nil {
			return
		}
	}
}

type notifModel struct {
	client        *sshUdpClient
	cursorPos     *string
	tmuxPaneId    string
	tmuxColumns   int
	borderStyle   lipgloss.Style
	statusStyle   lipgloss.Style
	errorStyle    lipgloss.Style
	tipsStyle     lipgloss.Style
	renderedLines int
	clientExiting atomic.Bool
	renderMutex   sync.Mutex
}

func newNotifModel(client *sshUdpClient, tmuxPaneId string, tmuxColumns int) *notifModel {
	return &notifModel{
		client:      client,
		cursorPos:   client.notifInterceptor.cursorPos.Load(),
		tmuxPaneId:  tmuxPaneId,
		tmuxColumns: tmuxColumns,
		borderStyle: lipgloss.NewStyle().BorderStyle(lipgloss.NormalBorder()).BorderForeground(cyanColor).Padding(0, 1, 0, 1),
		statusStyle: lipgloss.NewStyle().Foreground(magentaColor),
		errorStyle:  lipgloss.NewStyle().Foreground(lipgloss.Color("240")),
		tipsStyle:   lipgloss.NewStyle().Faint(true),
	}
}

func (m *notifModel) renderView(exiting, redrawing bool) {
	m.renderMutex.Lock()
	defer m.renderMutex.Unlock()
	if !exiting && m.clientExiting.Load() {
		return
	}

	var buf bytes.Buffer
	buf.WriteString(ansi.HideCursor)
	if m.client.notifInterceptor.noticeOnTop {
		if m.cursorPos == nil {
			buf.WriteString(ansi.SaveCurrentCursorPosition)
		}
		buf.WriteString(ansi.CursorHomePosition)
	} else if m.renderedLines > 1 {
		buf.WriteString(ansi.CursorUp(m.renderedLines - 1))
	}

	viewStr := m.getView(redrawing)
	lines := strings.Split(viewStr, "\n")
	buf.WriteByte('\r')
	for i, line := range lines {
		line = ansi.Truncate(line, m.getWidth(), "")
		buf.WriteString(line)
		if ansi.StringWidth(line) < m.getWidth() {
			buf.WriteString(ansi.EraseLineRight)
		}
		if i < len(lines)-1 {
			buf.WriteString("\r\n")
		}
	}

	if len(lines) < m.renderedLines {
		for i := len(lines); i < m.renderedLines; i++ {
			buf.WriteString("\r\n")
			buf.WriteString(ansi.EraseLineRight)
		}
		buf.WriteString(ansi.CursorUp(m.renderedLines - len(lines)))
	}

	if m.client.notifInterceptor.noticeOnTop {
		if m.cursorPos != nil {
			buf.WriteString(fmt.Sprintf("\x1b[%sH", *m.cursorPos))
		} else {
			buf.WriteString(ansi.RestoreCurrentCursorPosition)
		}
		buf.WriteString(ansi.ShowCursor)
	} else if !m.client.isReconnectTimeout() || exiting {
		buf.WriteString(ansi.ShowCursor)
	}

	if exiting {
		buf.WriteString("\r\n")
	}
	m.renderedLines = len(lines)

	if m.tmuxPaneId != "" {
		writeTmuxOutput(buf.Bytes(), m.tmuxPaneId)
	} else {
		_, _ = os.Stderr.Write(buf.Bytes())
	}
}

func (m *notifModel) getView(redrawing bool) string {
	if !m.client.isReconnectTimeout() && !redrawing || m.clientExiting.Load() {
		return ""
	}

	var statusMsg string
	if redrawing {
		statusMsg = "Congratulations, you have successfully reconnected to the server. The screen is being redrawn, please wait..."
	} else {
		statusMsg = m.client.getConnLostStatus()
	}

	var buf strings.Builder
	if !m.client.notifInterceptor.showFullNotif.Load() {
		buf.WriteString(lipgloss.NewStyle().Background(blueColor).Foreground(lipgloss.Color("16")).Render(statusMsg))
		if !m.clientExiting.Load() && !redrawing {
			buf.WriteString(lipgloss.NewStyle().Background(blueColor).Foreground(lipgloss.Color("241")).
				Render(" Ctrl+A to toggle full notifications."))
		}
		text := buf.String()
		if ansi.StringWidth(text) < m.getWidth() {
			return lipgloss.NewStyle().Width(m.getWidth()).Background(blueColor).Render(text)
		} else {
			return text
		}
	}

	buf.WriteString(m.statusStyle.Render(statusMsg))
	if !m.clientExiting.Load() && !redrawing {
		if err := m.getReconnectError(); err != nil {
			buf.WriteByte('\n')
			buf.WriteString(m.errorStyle.Render("Last reconnect error: " + err.Error()))
		}
		buf.WriteByte('\n')
		buf.WriteString(m.tipsStyle.Render("No longer need to reconnect to the server? Press Ctrl+C to exit."))
	}

	return lipgloss.PlaceHorizontal(m.getWidth(), lipgloss.Center, m.borderStyle.Render(buf.String()))
}

func (m *notifModel) getWidth() int {
	if m.tmuxColumns > 0 {
		return m.tmuxColumns
	}
	return m.client.sshConn.session.GetTerminalWidth()
}

func (m *notifModel) getReconnectError() error {
	client := m.client
	err := client.reconnectError.Load()
	for client.proxyClient != nil {
		client = client.proxyClient
		if e := client.reconnectError.Load(); e != nil {
			err = e
		}
	}
	if err != nil {
		return *err
	}
	return nil
}

type notifInterceptor struct {
	sshConn       *sshConnection
	inputBufChan  chan []byte
	noticeOnTop   bool
	showFullNotif atomic.Bool
	intMutex      sync.Mutex
	intFlag       atomic.Bool
	intChan       chan byte
	cursorPos     atomic.Pointer[string]
	tmuxFlag      atomic.Bool
	tmuxPaneId    atomic.Pointer[string]
	tmuxLeftBuf   []byte
}

func (ni *notifInterceptor) interceptInput() <-chan byte {
	ni.intMutex.Lock()
	defer ni.intMutex.Unlock()
	if ni.intChan == nil {
		ni.intChan = make(chan byte, 1)
	}
	ni.intFlag.Store(true)
	return ni.intChan
}

func (ni *notifInterceptor) cancelIntercept() {
	ni.intMutex.Lock()
	defer ni.intMutex.Unlock()
	ni.intFlag.Store(false)
}

func (ni *notifInterceptor) handleUserInput(input []byte) {
	buf := input

	if ni.tmuxFlag.Load() {
		if ni.tmuxLeftBuf != nil {
			buf = append(ni.tmuxLeftBuf, buf...)
		}
		var detach bool
		var paneId string
		buf, ni.tmuxLeftBuf, paneId, detach = handleAndDecodeTmuxInput(buf)
		if detach {
			ni.sshConn.forceExit(kExitCodeTmuxDetach, "Exit due to connection was lost and detach from tmux integration")
			return
		}
		if paneId == "" {
			return
		}
		tmuxPaneId := ni.tmuxPaneId.Load()
		if tmuxPaneId == nil {
			tmuxDebug("obtained tmux pane id [%s] from input [%s]", paneId, string(input))
			ni.tmuxPaneId.Store(&paneId)
		} else if *tmuxPaneId != paneId {
			return
		}
	} else if ni.tmuxLeftBuf != nil {
		ni.tmuxLeftBuf = nil
	}

	n := len(buf)
	if n == 1 && ni.intChan != nil {
		select {
		case ni.intChan <- buf[0]:
		default:
		}
		return
	}
	if n > 5 && buf[0] == '\x1b' && buf[1] == '[' && buf[n-1] == 'R' { // cursor pos
		curPos := string(buf[2 : n-1])
		ni.cursorPos.Store(&curPos)
		return
	}
}

func (ni *notifInterceptor) forwardInput(reader io.Reader, writer io.WriteCloser) {
	ni.inputBufChan = make(chan []byte, 10)
	defer close(ni.inputBufChan)
	go func() {
		defer func() { _ = writer.Close() }()
		for buf := range ni.inputBufChan {
			_ = writeAll(writer, buf)
		}
	}()

	buffer := make([]byte, 32*1024)
	for {
		n, err := reader.Read(buffer)
		if ni.intFlag.Load() {
			ni.handleUserInput(buffer[:n])
			continue
		}
		if n > 0 {
			var buf []byte
			if ni.tmuxLeftBuf != nil {
				buf = append(ni.tmuxLeftBuf, buffer[:n]...)
				ni.tmuxLeftBuf = nil
			} else {
				buf = make([]byte, n)
				copy(buf, buffer[:n])
			}
		out:
			for {
				select {
				case ni.inputBufChan <- buf:
					break out
				default:
					if ni.intFlag.Load() {
						ni.tmuxLeftBuf = buf
						break out
					}
					time.Sleep(10 * time.Millisecond)
				}
			}
		}
		if err != nil {
			break
		}
	}
	if ni.intChan != nil {
		close(ni.intChan)
	}
}

func (ni *notifInterceptor) discardPendingInput(discardMarker []byte) []byte {
	if len(ni.inputBufChan) == 0 {
		ni.inputBufChan <- discardMarker
		return nil
	}

	var input []byte
out:
	for {
		select {
		case buf := <-ni.inputBufChan:
			input = append(input, buf...)
		case <-time.After(21 * time.Millisecond):
			break out
		}
	}

	ni.inputBufChan <- discardMarker
	return input
}

func (ni *notifInterceptor) forwardOutput(reader io.Reader, writer io.WriteCloser) {
	defer func() { _ = writer.Close() }()
	buffer := make([]byte, 32*1024)
	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			for ni.intFlag.Load() {
				time.Sleep(10 * time.Millisecond)
			}
			_ = writeAll(writer, buffer[:n])
		}
		if err != nil {
			break
		}
	}
}

func setupUdpNotification(sshConn *sshConnection) {
	if lastJumpUdpClient == nil {
		return
	}
	if !isTerminal || !sshConn.tty {
		return
	}

	inReader, inWriter := io.Pipe()
	outReader, outWriter := io.Pipe()
	errReader, errWriter := io.Pipe()

	ni := notifInterceptor{sshConn: sshConn}
	ni.noticeOnTop = strings.ToLower(getExOptionConfig(sshConn.param.args, "ShowNotificationOnTop")) != "no"
	ni.showFullNotif.Store(strings.ToLower(getExOptionConfig(sshConn.param.args, "ShowFullNotifications")) != "no")

	go ni.forwardInput(inReader, sshConn.serverIn)
	go ni.forwardOutput(sshConn.serverOut, outWriter)
	go ni.forwardOutput(sshConn.serverErr, errWriter)

	lastJumpUdpClient.notifInterceptor = &ni
	sshConn.serverIn, sshConn.serverOut, sshConn.serverErr = inWriter, outReader, errReader
}

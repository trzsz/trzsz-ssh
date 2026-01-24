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
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

func showConnectionLostNotif(client *sshUdpClient) {
	tmux := isRunningTmuxIntegration()
	client.notifInterceptor.tmuxFlag.Store(tmux)
	client.notifInterceptor.cursorPos.Store(nil)

	client.debug("start intercepting user input")
	client.notifInterceptor.interceptFlag.Store(true)
	defer func() {
		client.debug("releasing intercepted user input")
		client.notifInterceptor.filterESC6n.Store(true)
		client.notifInterceptor.interceptFlag.Store(false)
	}()
	go interactWithUserInput(client)

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

	// clear the area below the cursor before redrawing the screen
	if tmuxPaneId != "" {
		writeTmuxOutput([]byte(ansi.EraseScreenBelow), tmuxPaneId)
	} else {
		_, _ = os.Stderr.WriteString(ansi.EraseScreenBelow)
	}

	_, _ = doWithTimeout(func() (int, error) {
		client.debug("requesting screen redraw")
		client.sshConn.Load().session.RedrawScreen()
		client.debug("screen redraw completed")
		return 0, nil
	}, client.reconnectTimeout)
	notif.renderView(false, false)
}

func interactWithUserInput(client *sshUdpClient) {
	for client.isReconnectTimeout() {
		select {
		case ch, ok := <-client.notifInterceptor.interceptChan:
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

	width := m.getWidth()
	var buf bytes.Buffer
	buf.WriteString(ansi.ResetModeAutoWrap)
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
	buf.WriteString(ansi.SetModeAutoWrap)

	if exiting {
		buf.WriteString("\r\n")
	}
	m.renderedLines = len(lines)

	if m.tmuxPaneId != "" {
		writeTmuxOutput(buf.Bytes(), m.tmuxPaneId)
	} else {
		if width != m.getWidth() {
			// Terminal column changed, skip this render to avoid misaligned output
			// Note: due to asynchronous terminal size changes (e.g., lock screen or resize),
			// This only reduces misalignment risk; it can't guarantee 100% correct output.
			m.client.debug("skipping render: column changed from %d to %d", width, m.getWidth())
			return
		}
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
		if err := m.client.GetLastReconnectError(); err != nil {
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
	return m.client.sshConn.Load().session.GetTerminalWidth()
}

type notifInterceptor struct {
	client        *sshUdpClient
	inputBufChan  chan []byte
	inputBufChMu  sync.Mutex
	noticeOnTop   bool
	showFullNotif atomic.Bool
	interceptFlag atomic.Bool
	interceptChan chan byte
	cursorPos     atomic.Pointer[string]
	tmuxFlag      atomic.Bool
	tmuxPaneId    atomic.Pointer[string]
	tmuxLeftBuf   []byte
	filterESC6n   atomic.Bool
}

func (ni *notifInterceptor) handleUserInput(input []byte) {
	if enableDebugLogging {
		ni.client.debug("discard user input %s", strconv.QuoteToASCII(string(input)))
	}

	buf := input
	if ni.tmuxFlag.Load() {
		if ni.tmuxLeftBuf != nil {
			buf = append(ni.tmuxLeftBuf, buf...)
		}
		var detach bool
		var paneId string
		buf, ni.tmuxLeftBuf, paneId, detach = handleAndDecodeTmuxInput(buf)
		if detach {
			ni.client.sshConn.Load().forceExit(kExitCodeTmuxDetach, "Exit due to connection was lost and detach from tmux integration")
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
	if n == 1 {
		select {
		case ni.interceptChan <- buf[0]:
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
	defer func() {
		close(ni.interceptChan)
		ni.inputBufChMu.Lock()
		defer ni.inputBufChMu.Unlock()
		close(ni.inputBufChan)
		ni.inputBufChan = nil
	}()

	go func() {
		defer func() { _ = writer.Close() }()
		for buf := range ni.inputBufChan {
			if err := writeAll(writer, buf); err != nil {
				warning("udp forward input failed: %v", err)
			}
		}
	}()

	buffer := make([]byte, 32*1024)
	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			if ni.interceptFlag.Load() {
				ni.handleUserInput(buffer[:n])
				continue
			}
			var buf []byte
			if ni.tmuxLeftBuf != nil {
				buf = append(ni.tmuxLeftBuf, buffer[:n]...)
				ni.tmuxLeftBuf = nil
			} else {
				buf = make([]byte, n)
				copy(buf, buffer[:n])
			}
			if ni.filterESC6n.Load() {
				// stop filtering ESC[6n once the user provides real input and starts interacting with the remote program again.
				ni.filterESC6n.Store(false)
			}
		out:
			for {
				select {
				case ni.inputBufChan <- buf:
					break out
				default:
					if ni.interceptFlag.Load() {
						ni.handleUserInput(buf)
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
}

func (ni *notifInterceptor) discardPendingInput(discardMarker []byte) []byte {
	ni.inputBufChMu.Lock()
	defer ni.inputBufChMu.Unlock()
	if ni.inputBufChan == nil {
		return nil
	}

	if ni.client == ni.client.sshConn.Load().client { // the last ssh client is udp client
		defer func() { ni.inputBufChan <- discardMarker }()
	}

	if len(ni.inputBufChan) == 0 {
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

	return input
}

func (ni *notifInterceptor) forwardOutput(reader io.Reader, writer io.WriteCloser) {
	defer func() { _ = writer.Close() }()
	cache := &outputCache{client: ni.client}
	buffer := make([]byte, 32*1024)
	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			if ni.interceptFlag.Load() {
				cache.appendOutput(buffer[:n])
			} else {
				if len(cache.chunks) > 0 {
					if err := cache.flushOutput(writer); err != nil {
						break
					}
				}
				buf := buffer[:n]
				if ni.filterESC6n.Load() {
					if enableDebugLogging {
						n := bytes.Count(buf, []byte("\x1b[6n"))
						if n > 0 {
							ni.client.debug("filtered %d ESC[6n sequence(s) from live output", n)
						}
					}
					buf = bytes.ReplaceAll(buf, []byte("\x1b[6n"), []byte(""))
				}
				if err := writeAll(writer, buf); err != nil {
					break
				}
			}
		}
		if err != nil {
			break
		}
	}
	_ = cache.flushOutput(writer)
}

type outputCache struct {
	client *sshUdpClient
	chunks [][]byte
}

func (c *outputCache) appendOutput(data []byte) {
	for len(data) > 0 {
		var last []byte
		if len(c.chunks) > 0 {
			last = c.chunks[len(c.chunks)-1]
		}
		if len(last) == cap(last) {
			last = make([]byte, 0, max(len(data), 64*1024))
			c.chunks = append(c.chunks, last)
		}

		n := min(len(data), cap(last)-len(last))
		c.chunks[len(c.chunks)-1] = append(last, data[:n]...)
		data = data[n:]
	}
}

func (c *outputCache) flushOutput(writer io.Writer) error {
	if c.chunks == nil {
		return nil
	}

	if enableDebugLogging {
		cacheSize, filteredCount := 0, 0
		for _, chunk := range c.chunks {
			cacheSize += len(chunk)
			filteredCount += bytes.Count(chunk, []byte("\x1b[6n"))
		}
		if cacheSize > 0 {
			c.client.debug("session output cache size [%d]", cacheSize)
		}
		if filteredCount > 0 {
			c.client.debug("filtered %d ESC[6n sequence(s) from cache output", filteredCount)
		}
	}

	for _, chunk := range c.chunks {
		chunk = bytes.ReplaceAll(chunk, []byte("\x1b[6n"), []byte(""))
		if len(chunk) > 0 {
			if _, err := writer.Write(chunk); err != nil {
				return err
			}
		}
	}
	c.chunks = nil
	return nil
}

func setupUdpNotification(sshConn *sshConnection) {
	if lastJumpUdpClient == nil || !isTerminal || !sshConn.tty {
		return
	}

	ni := notifInterceptor{client: lastJumpUdpClient, interceptChan: make(chan byte, 1)}
	ni.noticeOnTop = strings.ToLower(getExOptionConfig(sshConn.param.args, "ShowNotificationOnTop")) != "no"
	ni.showFullNotif.Store(strings.ToLower(getExOptionConfig(sshConn.param.args, "ShowFullNotifications")) != "no")

	inReader, inWriter := io.Pipe()
	outReader, outWriter := io.Pipe()
	errReader, errWriter := io.Pipe()

	go ni.forwardInput(inReader, sshConn.serverIn)
	go ni.forwardOutput(sshConn.serverOut, outWriter)
	go ni.forwardOutput(sshConn.serverErr, errWriter)

	lastJumpUdpClient.notifInterceptor = &ni
	sshConn.serverIn, sshConn.serverOut, sshConn.serverErr = inWriter, outReader, errReader
}

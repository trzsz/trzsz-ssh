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
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/shlex"
	"github.com/trzsz/tsshd/tsshd"
	"golang.org/x/crypto/ssh"
)

const (
	kUdpModeNo   = 1
	kUdpModeKcp  = 2
	kUdpModeQuic = 3
)

const kDefaultUdpAliveTimeout = 100 * time.Second

const kDefaultProxyAliveTimeout = 24 * time.Hour

type sshUdpClient struct {
	client         tsshd.Client
	wg             sync.WaitGroup
	busMutex       sync.Mutex
	busStream      net.Conn
	sessionMutex   sync.Mutex
	sessionID      atomic.Uint64
	sessionMap     map[uint64]*sshUdpSession
	channelMutex   sync.Mutex
	channelMap     map[string]chan ssh.NewChannel
	lastAliveTime  atomic.Pointer[time.Time]
	aliveTimeout   time.Duration
	closed         atomic.Bool
	reconnecting   atomic.Bool
	lostConnection atomic.Bool
	reconnectTimes atomic.Uint64
	connectTimeout time.Duration
	mainUdpSession *sshUdpSession
	reconnectError atomic.Pointer[error]
}

func (c *sshUdpClient) newStream(cmd string) (stream net.Conn, err error) {
	done := make(chan struct{}, 1)
	go func() {
		defer func() {
			if err != nil && stream != nil {
				stream.Close()
			}
			done <- struct{}{}
			close(done)
		}()
		stream, err = c.client.NewStream()
		if err != nil {
			err = fmt.Errorf("new stream [%s] failed: %v", cmd, err)
			return
		}
		if err = tsshd.SendCommand(stream, cmd); err != nil {
			err = fmt.Errorf("send command [%s] failed: %v", cmd, err)
			return
		}
		if err = tsshd.RecvError(stream); err != nil {
			err = fmt.Errorf("new stream [%s] error: %v", cmd, err)
			return
		}
	}()

	select {
	case <-time.After(c.connectTimeout):
		err = fmt.Errorf("new stream [%s] timeout", cmd)
	case <-done:
	}
	return
}

func (c *sshUdpClient) Wait() error {
	c.wg.Wait()
	return nil
}

func (c *sshUdpClient) Close() error {
	if c.closed.Load() {
		return nil
	}
	c.closed.Store(true)

	done := make(chan struct{}, 1)
	go func() {
		defer close(done)
		c.busMutex.Lock()
		defer c.busMutex.Unlock()
		if err := tsshd.SendCommand(c.busStream, "close"); err != nil {
			warning("send close command failed: %v", err)
		}
		c.busStream.Close()
		time.Sleep(500 * time.Millisecond) // give udp some time
		done <- struct{}{}
	}()

	select {
	case <-time.After(1 * time.Second):
	case <-done:
	}
	return c.client.Close()
}

func (c *sshUdpClient) NewSession() (SshSession, error) {
	stream, err := c.newStream("session")
	if err != nil {
		return nil, err
	}
	c.wg.Add(1)
	udpSession := &sshUdpSession{client: c, stream: stream, envs: make(map[string]string)}
	udpSession.wg.Add(1)
	c.sessionMutex.Lock()
	defer c.sessionMutex.Unlock()
	udpSession.id = c.sessionID.Add(1) - 1
	c.sessionMap[udpSession.id] = udpSession
	return udpSession, nil
}

func (c *sshUdpClient) DialTimeout(network, addr string, timeout time.Duration) (net.Conn, error) {
	stream, err := c.newStream("dial")
	if err != nil {
		return nil, err
	}
	msg := tsshd.DialMessage{
		Network: network,
		Addr:    addr,
		Timeout: timeout,
	}
	if err := tsshd.SendMessage(stream, &msg); err != nil {
		stream.Close()
		return nil, fmt.Errorf("send dial message failed: %v", err)
	}
	if err := tsshd.RecvError(stream); err != nil {
		stream.Close()
		return nil, err
	}
	c.wg.Add(1)
	return &sshUdpConn{Conn: stream, client: c}, nil
}

func (c *sshUdpClient) Listen(network, addr string) (net.Listener, error) {
	stream, err := c.newStream("listen")
	if err != nil {
		return nil, err
	}
	msg := tsshd.ListenMessage{
		Network: network,
		Addr:    addr,
	}
	if err := tsshd.SendMessage(stream, &msg); err != nil {
		stream.Close()
		return nil, fmt.Errorf("send listen message failed: %v", err)
	}
	if err := tsshd.RecvError(stream); err != nil {
		stream.Close()
		return nil, err
	}
	c.wg.Add(1)
	return &sshUdpListener{client: c, stream: stream}, nil
}

func (c *sshUdpClient) HandleChannelOpen(channelType string) <-chan ssh.NewChannel {
	c.channelMutex.Lock()
	defer c.channelMutex.Unlock()
	if _, ok := c.channelMap[channelType]; ok {
		return nil
	}
	switch channelType {
	case kAgentChannelType, kX11ChannelType:
		ch := make(chan ssh.NewChannel)
		c.channelMap[channelType] = ch
		return ch
	default:
		warning("channel type [%s] is not supported yet", channelType)
		return nil
	}
}

func (c *sshUdpClient) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	return false, nil, fmt.Errorf("ssh udp client SendRequest is not supported yet")
}

func (c *sshUdpClient) sendBusCommand(command string) error {
	c.busMutex.Lock()
	defer c.busMutex.Unlock()
	return tsshd.SendCommand(c.busStream, command)
}

func (c *sshUdpClient) sendBusMessage(command string, msg any) error {
	c.busMutex.Lock()
	defer c.busMutex.Unlock()
	if err := tsshd.SendCommand(c.busStream, command); err != nil {
		return err
	}
	return tsshd.SendMessage(c.busStream, msg)
}

func (c *sshUdpClient) udpKeepAlive(udpProxy bool, intervalTimeout time.Duration) {
	reconnectTimeout := intervalTimeout * 3
	go func() {
		for {
			if err := c.sendBusCommand("alive"); err != nil {
				warning("udp keep alive failed: %v", err)
			}
			time.Sleep(intervalTimeout)
			if c.closed.Load() {
				return
			}
		}
	}()
	for {
		if lastAliveTime := c.lastAliveTime.Load(); lastAliveTime != nil {
			elapsedTime := time.Since(*lastAliveTime)
			if elapsedTime > c.aliveTimeout {
				warning("udp keep alive timeout")
				c.exit(125)
				return
			}

			if udpProxy && !c.reconnecting.Load() && elapsedTime > reconnectTimeout {
				debug("udp try to reconnect")
				c.reconnecting.Store(true)
				c.reconnectTimes.Add(1)
				if err := c.client.Reconnect(); err != nil {
					c.reconnectError.Store(&err)
				}
				go func() {
					time.Sleep(intervalTimeout * 3)
					c.reconnecting.Store(false)
				}()
			}

			if c.mainUdpSession != nil && !c.lostConnection.Load() && elapsedTime > 15*time.Second {
				c.lostConnection.Store(true)
				go c.handleLostConnection(udpProxy)
			}
		}

		time.Sleep(intervalTimeout)
		if c.closed.Load() {
			return
		}
	}
}

func (c *sshUdpClient) handleBusEvent() {
	for {
		command, err := tsshd.RecvCommand(c.busStream)
		if c.closed.Load() {
			return
		}
		if err != nil {
			warning("recv bus command failed: %v", err)
			return
		}
		switch command {
		case "exit":
			c.handleExitEvent()
		case "error":
			c.handleErrorEvent()
		case "channel":
			c.handleChannelEvent()
		case "alive":
			now := time.Now()
			c.lastAliveTime.Store(&now)
			if c.reconnecting.Load() || c.reconnectTimes.Load() > 0 {
				debug("udp successfully reconnected")
				c.reconnecting.Store(false)
				c.reconnectTimes.Store(0)
				c.reconnectError.Store(nil)
				c.lostConnection.Store(false)
			}
		default:
			warning("unknown command bus command: %s", command)
		}
	}
}

func (c *sshUdpClient) handleExitEvent() {
	var exitMsg tsshd.ExitMessage
	if err := tsshd.RecvMessage(c.busStream, &exitMsg); err != nil {
		warning("recv exit message failed: %v", err)
		return
	}

	c.sessionMutex.Lock()
	defer c.sessionMutex.Unlock()

	udpSession, ok := c.sessionMap[exitMsg.ID]
	if !ok {
		warning("invalid or exited session id: %d", exitMsg.ID)
		return
	}
	udpSession.exit(exitMsg.ExitCode)

	delete(c.sessionMap, exitMsg.ID)
	c.wg.Done()
}

func (c *sshUdpClient) handleErrorEvent() {
	var errMsg tsshd.ErrorMessage
	if err := tsshd.RecvMessage(c.busStream, &errMsg); err != nil {
		warning("recv error message failed: %v", err)
		return
	}
	warning("udp error: %s", errMsg.Msg)
}

func (c *sshUdpClient) handleChannelEvent() {
	var channelMsg tsshd.ChannelMessage
	if err := tsshd.RecvMessage(c.busStream, &channelMsg); err != nil {
		warning("recv channel message failed: %v", err)
		return
	}
	c.channelMutex.Lock()
	defer c.channelMutex.Unlock()
	if ch, ok := c.channelMap[channelMsg.ChannelType]; ok {
		go func() {
			ch <- &sshUdpNewChannel{
				client:      c,
				channelType: channelMsg.ChannelType,
				id:          channelMsg.ID}
		}()
	} else {
		warning("channel [%s] has no handler", channelMsg.ChannelType)
	}
}

func (c *sshUdpClient) exit(code int) {
	c.closed.Store(true)
	c.sessionMutex.Lock()
	defer c.sessionMutex.Unlock()
	for _, udpSession := range c.sessionMap {
		udpSession.exit(code)
		c.wg.Done()
	}
	c.sessionMap = make(map[uint64]*sshUdpSession)
}

func (c *sshUdpClient) handleLostConnection(udpProxy bool) {
	ctrlC := c.mainUdpSession.interceptCtrlC()
	defer c.mainUdpSession.cancelIntercept()

	go func() {
		for c.lostConnection.Load() {
			select {
			case _, ok := <-ctrlC:
				if ok {
					warning("UDP disconnected and Ctrl+C to exit")
					c.exit(126)
					return
				}
			case <-time.After(200 * time.Millisecond):
			}
		}
	}()

	model := &noticeModel{
		client:      c,
		udpProxy:    udpProxy,
		borderStyle: lipgloss.NewStyle().BorderStyle(lipgloss.NormalBorder()).BorderForeground(cyanColor).Padding(0, 1, 0, 1),
		statusStyle: lipgloss.NewStyle().Foreground(magentaColor),
		errorStyle:  lipgloss.NewStyle().Foreground(lipgloss.Color("240")),
		tipsStyle:   lipgloss.NewStyle().Faint(true),
	}
	oriDebug, oriWarning := debug, warning
	defer func() {
		debug, warning = oriDebug, oriWarning
	}()
	debug, warning = model.debug, model.warning
	tea.NewProgram(model, tea.WithInput(nil)).Run()
}

type noticeModel struct {
	client      *sshUdpClient
	udpProxy    bool
	borderStyle lipgloss.Style
	statusStyle lipgloss.Style
	errorStyle  lipgloss.Style
	tipsStyle   lipgloss.Style
	extraMsg    string
}

func (m *noticeModel) Init() tea.Cmd {
	return tickEvery(200 * time.Millisecond)
}

func (m *noticeModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if !m.client.lostConnection.Load() {
		return m, tea.Quit
	}
	if _, ok := msg.(tickMsg); ok {
		return m, tickEvery(200 * time.Millisecond)
	}
	return m, nil
}

func (m *noticeModel) View() string {
	var buf strings.Builder
	if !m.client.lostConnection.Load() {
		buf.WriteString(m.statusStyle.Render("Reconnected to the server, you can refresh your screen to continue..."))
		buf.WriteByte('\n')
		buf.WriteString(m.tipsStyle.Render("Press Enter or Ctrl+C on the command line, type :redraw! in vim, etc."))
		return m.borderStyle.Render(buf.String()) + "\n"
	}

	if t := m.client.lastAliveTime.Load(); t != nil {
		format := "Oops, looks like the connection to the server was lost, trying to reconnect for %d/%d seconds."
		if !m.udpProxy {
			format = "Oops, looks like the connection to the server was lost, auto exit countdown %d/%d seconds."
		}
		buf.WriteString(m.statusStyle.Render(fmt.Sprintf(format, time.Since(*t)/time.Second, m.client.aliveTimeout/time.Second)))
		buf.WriteByte('\n')
	}
	if err := m.client.reconnectError.Load(); err != nil {
		buf.WriteString(m.errorStyle.Render("Last reconnect error: " + (*err).Error()))
		buf.WriteByte('\n')
	}
	buf.WriteString(m.tipsStyle.Render("No longer need to reconnect to the server? Press Ctrl+C to exit."))
	if m.extraMsg != "" {
		buf.WriteByte('\n')
		buf.WriteString(m.extraMsg)
	}

	return m.borderStyle.Render(buf.String())
}

func (m *noticeModel) debug(format string, a ...any) {
	if !enableDebugLogging {
		return
	}
	m.extraMsg = fmt.Sprintf(fmt.Sprintf("\033[0;36mdebug:\033[0m %s", format), a...)
}

func (m *noticeModel) warning(format string, a ...any) {
	if !envbleWarningLogging {
		return
	}
	m.extraMsg = fmt.Sprintf(fmt.Sprintf("\033[0;33mWarning: %s\033[0m", format), a...)
}

type sshUdpSession struct {
	id      uint64
	wg      sync.WaitGroup
	client  *sshUdpClient
	stream  net.Conn
	pty     bool
	height  int
	width   int
	envs    map[string]string
	started bool
	closed  bool
	stdin   io.Reader
	stdout  io.WriteCloser
	stderr  net.Conn
	code    int
	x11     *x11Request
	agent   *agentRequest
	intMu   sync.Mutex
	intCnt  atomic.Int32
	ctrlC   chan struct{}
}

func (s *sshUdpSession) Wait() error {
	s.wg.Wait()
	if s.code != 0 {
		return fmt.Errorf("udp session exit with %d", s.code)
	}
	return nil
}

func (s *sshUdpSession) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	if s.stdout != nil {
		_ = s.stdout.Close()
	}
	if s.stderr != nil {
		_ = s.stderr.Close()
	}

	var err error
	done := make(chan struct{}, 1)
	go func() {
		defer close(done)
		err = s.stream.Close()
		time.Sleep(500 * time.Millisecond) // give udp some time
		done <- struct{}{}
	}()
	select {
	case <-time.After(1 * time.Second):
	case <-done:
	}
	return err
}

func (s *sshUdpSession) Shell() error {
	msg := tsshd.StartMessage{
		ID:    s.id,
		Pty:   s.pty,
		Shell: true,
		Cols:  s.width,
		Rows:  s.height,
		Envs:  s.envs,
	}
	return s.startSession(&msg)
}

func (s *sshUdpSession) Run(cmd string) error {
	if err := s.Start(cmd); err != nil {
		return err
	}
	return s.Wait()
}

func (s *sshUdpSession) Start(cmd string) error {
	args, err := shlex.Split(cmd)
	if err != nil {
		return fmt.Errorf("split cmd [%s] failed: %v", cmd, err)
	}
	if len(args) == 0 {
		return fmt.Errorf("cmd [%s] is empty", cmd)
	}
	msg := tsshd.StartMessage{
		ID:    s.id,
		Pty:   s.pty,
		Shell: false,
		Name:  args[0],
		Args:  args[1:],
		Envs:  s.envs,
	}
	return s.startSession(&msg)
}

func (s *sshUdpSession) forwardStdin() {
	bufChan := make(chan []byte, 128)
	defer close(bufChan)
	go func() {
		for buf := range bufChan {
			writeAll(s.stream, buf)
		}
	}()

	buffer := make([]byte, 32*1024)
	for {
		n, err := s.stdin.Read(buffer)
		if n == 1 && buffer[0] == '\x03' && s.intCnt.Load() > 0 && s.ctrlC != nil { // ctrl + c
			s.ctrlC <- struct{}{}
			continue
		}
		if n > 0 {
			buf := make([]byte, n)
			copy(buf, buffer[:n])
		out:
			for {
				select {
				case <-time.After(100 * time.Millisecond):
					if s.intCnt.Load() > 0 {
						break out
					}
				case bufChan <- buf:
					break out
				}
			}
		}
		if err != nil {
			break
		}
	}
	if s.ctrlC != nil {
		close(s.ctrlC)
	}
}

func (s *sshUdpSession) forwardStdout() {
	defer s.stdout.Close()
	buffer := make([]byte, 32*1024)
	for {
		n, err := s.stream.Read(buffer)
		if n > 0 {
			for s.intCnt.Load() > 0 {
				time.Sleep(10 * time.Millisecond)
			}
			writeAll(s.stdout, buffer[:n])
		}
		if err != nil {
			break
		}
	}
}

func (s *sshUdpSession) interceptCtrlC() <-chan struct{} {
	s.intMu.Lock()
	defer s.intMu.Unlock()
	if s.ctrlC == nil {
		s.ctrlC = make(chan struct{}, 1)
	}
	s.intCnt.Add(1)
	return s.ctrlC
}

func (s *sshUdpSession) cancelIntercept() {
	s.intMu.Lock()
	defer s.intMu.Unlock()
	s.intCnt.Add(-1)
}

func (s *sshUdpSession) startSession(msg *tsshd.StartMessage) error {
	if s.started {
		return fmt.Errorf("session already started")
	}
	s.started = true
	if s.x11 != nil {
		msg.X11 = &tsshd.X11Request{
			ChannelType:      kX11ChannelType,
			SingleConnection: s.x11.SingleConnection,
			AuthProtocol:     s.x11.AuthProtocol,
			AuthCookie:       s.x11.AuthCookie,
			ScreenNumber:     s.x11.ScreenNumber,
		}
	}
	if s.agent != nil {
		msg.Agent = &tsshd.AgentRequest{
			ChannelType: kAgentChannelType,
		}
	}
	if err := tsshd.SendMessage(s.stream, msg); err != nil {
		return fmt.Errorf("send session message failed: %v", err)
	}
	if err := tsshd.RecvError(s.stream); err != nil {
		return err
	}
	if s.stdin != nil {
		go s.forwardStdin()
	}
	if s.stdout != nil {
		go s.forwardStdout()
	}
	return nil
}

func (s *sshUdpSession) exit(code int) {
	s.code = code
	s.wg.Done()
	if s.stdout != nil {
		s.stdout.Close()
	}
	if s.stderr != nil {
		s.stderr.Close()
	}
}

func (s *sshUdpSession) WindowChange(height, width int) error {
	return s.client.sendBusMessage("resize", tsshd.ResizeMessage{
		ID:   s.id,
		Cols: width,
		Rows: height,
	})
}

func (s *sshUdpSession) Setenv(name, value string) error {
	s.envs[name] = value
	return nil
}

func (s *sshUdpSession) StdinPipe() (io.WriteCloser, error) {
	if s.stdin != nil {
		return nil, fmt.Errorf("stdin already set")
	}
	reader, writer := io.Pipe()
	s.stdin = reader
	return writer, nil
}

func (s *sshUdpSession) StdoutPipe() (io.Reader, error) {
	if s.stdout != nil {
		return nil, fmt.Errorf("stdout already set")
	}
	reader, writer := io.Pipe()
	s.stdout = writer
	return reader, nil
}

func (s *sshUdpSession) StderrPipe() (io.Reader, error) {
	if s.stderr != nil {
		return nil, fmt.Errorf("stderr already set")
	}
	stream, err := s.client.newStream("stderr")
	if err != nil {
		return nil, err
	}
	if err := tsshd.SendMessage(stream, tsshd.StderrMessage{ID: s.id}); err != nil {
		stream.Close()
		return nil, fmt.Errorf("send stderr message failed: %v", err)
	}
	if err := tsshd.RecvError(stream); err != nil {
		stream.Close()
		return nil, err
	}
	s.stderr = stream
	return s.stderr, nil
}

func (s *sshUdpSession) Output(cmd string) ([]byte, error) {
	stdout, err := s.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := s.Start(cmd); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		_, _ = buf.ReadFrom(stdout)
		wg.Done()
	}()
	if err := s.Wait(); err != nil {
		return nil, err
	}
	wg.Wait()
	return buf.Bytes(), nil
}

func (s *sshUdpSession) CombinedOutput(cmd string) ([]byte, error) {
	output, err := s.Output(cmd)
	if err != nil || s.stderr == nil {
		return output, err
	}
	var buf bytes.Buffer
	buf.Write(output)
	_, _ = buf.ReadFrom(s.stderr)
	return buf.Bytes(), nil
}

func (s *sshUdpSession) RequestPty(term string, height, width int, termmodes ssh.TerminalModes) error {
	s.pty = true
	s.envs["TERM"] = term
	s.height = height
	s.width = width
	return nil
}

func (s *sshUdpSession) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	switch name {
	case kX11RequestName:
		s.x11 = &x11Request{}
		if payload != nil {
			if err := ssh.Unmarshal(payload, s.x11); err != nil {
				return false, fmt.Errorf("unmarshal x11 request failed: %v", err)
			}
		}
		return true, nil
	case kAgentRequestName:
		s.agent = &agentRequest{}
		if payload != nil {
			if err := ssh.Unmarshal(payload, s.agent); err != nil {
				return false, fmt.Errorf("unmarshal agent request failed: %v", err)
			}
		}
		return true, nil
	default:
		return false, fmt.Errorf("ssh udp session SendRequest [%s] is not supported yet", name)
	}
}

type sshUdpListener struct {
	client *sshUdpClient
	stream net.Conn
	closed bool
}

func (l *sshUdpListener) Accept() (net.Conn, error) {
	var msg tsshd.AcceptMessage
	if err := tsshd.RecvMessage(l.stream, &msg); err != nil {
		return nil, fmt.Errorf("recv accept message failed: %v", err)
	}
	stream, err := l.client.newStream("accept")
	if err != nil {
		return nil, err
	}
	if err := tsshd.SendMessage(stream, &msg); err != nil {
		stream.Close()
		return nil, fmt.Errorf("send accept message failed: %v", err)
	}
	if err := tsshd.RecvError(stream); err != nil {
		stream.Close()
		return nil, err
	}
	l.client.wg.Add(1)
	return &sshUdpConn{Conn: stream, client: l.client}, nil
}

func (l *sshUdpListener) Close() error {
	if l.closed {
		return nil
	}
	l.closed = true
	l.client.wg.Done()
	return l.stream.Close()
}

func (l *sshUdpListener) Addr() net.Addr {
	return nil
}

type sshUdpConn struct {
	net.Conn
	client *sshUdpClient
	closed bool
}

func (c *sshUdpConn) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	c.client.wg.Done()
	return c.Conn.Close()
}

type sshUdpNewChannel struct {
	client      *sshUdpClient
	channelType string
	id          uint64
}

func (c *sshUdpNewChannel) Accept() (ssh.Channel, <-chan *ssh.Request, error) {
	stream, err := c.client.newStream("accept")
	if err != nil {
		return nil, nil, err
	}
	if err := tsshd.SendMessage(stream, &tsshd.AcceptMessage{ID: c.id}); err != nil {
		stream.Close()
		return nil, nil, fmt.Errorf("send accept message failed: %v", err)
	}
	if err := tsshd.RecvError(stream); err != nil {
		stream.Close()
		return nil, nil, err
	}
	c.client.wg.Add(1)
	return &sshUdpChannel{Conn: stream, client: c.client}, nil, nil
}

func (c *sshUdpNewChannel) Reject(reason ssh.RejectionReason, message string) error {
	return fmt.Errorf("ssh udp new channel Reject is not supported yet")
}

func (c *sshUdpNewChannel) ChannelType() string {
	return c.channelType
}

func (c *sshUdpNewChannel) ExtraData() []byte {
	return nil
}

type sshUdpChannel struct {
	net.Conn
	client *sshUdpClient
	closed bool
}

func (c *sshUdpChannel) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	c.client.wg.Done()
	return c.Conn.Close()
}

func (c *sshUdpChannel) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	} else {
		// close the entire stream since there is no half-close
		time.Sleep(200 * time.Millisecond)
		return c.Close()
	}
}

func (c *sshUdpChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	return false, fmt.Errorf("ssh udp channel SendRequest is not supported yet")
}

func (c *sshUdpChannel) Stderr() io.ReadWriter {
	warning("ssh udp channel Stderr is not supported yet")
	return nil
}

func sshUdpLogin(args *sshArgs, ss *sshClientSession, udpMode int, asProxy bool) (*sshClientSession, error) {
	defer ss.Close()

	udpProxy := strings.ToLower(getExOptionConfig(args, "UdpProxy")) != "no"
	serverInfo, err := startTsshdServer(args, ss, udpMode, udpProxy)
	if err != nil {
		return nil, err
	}

	connectTimeout := getConnectTimeout(args)
	client, err := tsshd.NewClient(ss.param.host, serverInfo, connectTimeout)
	if err != nil {
		return nil, err
	}

	udpClient := sshUdpClient{
		client:         client,
		sessionMap:     make(map[uint64]*sshUdpSession),
		channelMap:     make(map[string]chan ssh.NewChannel),
		connectTimeout: connectTimeout,
	}

	busStream, err := udpClient.newStream("bus")
	if err != nil {
		return nil, err
	}

	udpAliveTimeout := getUdpAliveTimeout(args, udpProxy)
	intervalTimeout := min(udpAliveTimeout/10, 10*time.Second)
	if udpProxy && intervalTimeout > 1*time.Second {
		intervalTimeout = 1 * time.Second
	}
	if err := tsshd.SendMessage(busStream, tsshd.BusMessage{Timeout: udpAliveTimeout, Interval: intervalTimeout}); err != nil {
		busStream.Close()
		return nil, fmt.Errorf("send bus message failed: %v", err)
	}
	if err := tsshd.RecvError(busStream); err != nil {
		busStream.Close()
		return nil, err
	}

	udpClient.busStream = busStream
	debug("udp login [%s] success", args.Destination)

	// keep alive
	if udpAliveTimeout > 0 {
		now := time.Now()
		udpClient.lastAliveTime.Store(&now)
		udpClient.aliveTimeout = udpAliveTimeout
		go udpClient.udpKeepAlive(udpProxy, intervalTimeout)
	}

	go udpClient.handleBusEvent()

	if asProxy {
		return &sshClientSession{client: &udpClient}, nil
	}

	// no exit while not executing remote command or running in background
	if args.NoCommand || args.Background {
		udpClient.wg.Add(1)
	}

	// if running as a proxy ( aka: stdio forward ), or if not executing remote command,
	// then there is no need to make a new session, so we return early here.
	if args.StdioForward != "" || args.NoCommand {
		return &sshClientSession{
			client: &udpClient,
			param:  ss.param,
			cmd:    ss.cmd,
			tty:    ss.tty,
		}, nil
	}

	udpSession, err := udpClient.NewSession()
	if err != nil {
		busStream.Close()
		return nil, fmt.Errorf("new session failed: %v", err)
	}
	udpClient.mainUdpSession = udpSession.(*sshUdpSession)

	serverIn, _ := udpSession.StdinPipe()
	serverOut, _ := udpSession.StdoutPipe()
	return &sshClientSession{
		client:    &udpClient,
		session:   udpSession,
		serverIn:  serverIn,
		serverOut: serverOut,
		serverErr: nil,
		param:     ss.param,
		cmd:       ss.cmd,
		tty:       ss.tty,
	}, nil
}

func startTsshdServer(args *sshArgs, ss *sshClientSession, udpMode int, udpProxy bool) (*tsshd.ServerInfo, error) {
	cmd := getTsshdCommand(args, udpMode, udpProxy)
	debug("tsshd command: %s", cmd)

	if err := ss.session.RequestPty("xterm-256color", 200, 800, ssh.TerminalModes{}); err != nil {
		return nil, fmt.Errorf("request pty for tsshd failed: %v", err)
	}

	if err := ss.session.Start(cmd); err != nil {
		return nil, fmt.Errorf("start tsshd failed: %v", err)
	}
	if err := ss.session.Wait(); err != nil {
		var builder strings.Builder
		if outMsg := readFromStream(ss.serverOut); outMsg != "" {
			builder.WriteString(outMsg)
		}
		if errMsg := readFromStream(ss.serverErr); errMsg != "" {
			if builder.Len() > 0 {
				builder.WriteString("\n")
			}
			builder.WriteString(errMsg)
		}
		if builder.Len() == 0 {
			builder.WriteString(err.Error())
		}
		return nil, fmt.Errorf("(Have you installed tsshd on your server? You may need to specify the path to tsshd.)\r\n"+
			"run tsshd failed: %s", builder.String())
	}

	output := readFromStream(ss.serverOut)
	if output == "" {
		if errMsg := readFromStream(ss.serverErr); errMsg != "" {
			return nil, fmt.Errorf("run tsshd failed: %s", errMsg)
		}
		return nil, fmt.Errorf("run tsshd failed: the output is empty")
	}
	pos := strings.LastIndexByte(output, '\a')
	if pos >= 0 {
		output = output[pos+1:]
	}
	pos = strings.IndexByte(output, '{')
	if pos >= 0 {
		output = output[pos:]
	}
	pos = strings.LastIndexByte(output, '}')
	if pos >= 0 {
		output = output[:pos+1]
	}
	output = strings.ReplaceAll(output, "\r", "")
	output = strings.ReplaceAll(output, "\n", "")
	if !strings.HasPrefix(output, "{") || !strings.HasSuffix(output, "}") {
		return nil, fmt.Errorf("run tsshd failed: %s", strconv.QuoteToASCII(output))
	}

	var info tsshd.ServerInfo
	if err := json.Unmarshal([]byte(output), &info); err != nil {
		return nil, fmt.Errorf("json unmarshal [%s] failed: %v", strconv.QuoteToASCII(output), err)
	}

	return &info, nil
}

func getTsshdCommand(args *sshArgs, udpMode int, udpProxy bool) string {
	var buf strings.Builder
	if args.TsshdPath != "" {
		buf.WriteString(args.TsshdPath)
	} else if tsshdPath := getExOptionConfig(args, "TsshdPath"); tsshdPath != "" {
		buf.WriteString(tsshdPath)
	} else {
		buf.WriteString("tsshd")
	}

	if udpMode == kUdpModeKcp {
		buf.WriteString(" --kcp")
	}
	if udpProxy {
		buf.WriteString(" --proxy")
	}

	if udpPort := getExOptionConfig(args, "UdpPort"); udpPort != "" {
		ports := strings.FieldsFunc(udpPort, func(c rune) bool {
			return unicode.IsSpace(c) || c == ',' || c == '-'
		})
		if len(ports) == 1 {
			port, err := strconv.Atoi(ports[0])
			if err != nil {
				warning("UdpPort %s is invalid: %v", udpPort, err)
			} else {
				buf.WriteString(fmt.Sprintf(" --port %d", port))
			}
		} else if len(ports) == 2 {
			for {
				lowPort, err := strconv.Atoi(ports[0])
				if err != nil {
					warning("UdpPort %s is invalid: %v", udpPort, err)
					break
				}
				highPort, err := strconv.Atoi(ports[1])
				if err != nil {
					warning("UdpPort %s is invalid: %v", udpPort, err)
					break
				}
				buf.WriteString(fmt.Sprintf(" --port %d-%d", lowPort, highPort))
				break // nolint:all
			}
		} else {
			warning("UdpPort %s is invalid", udpPort)
		}
	}

	return buf.String()
}

func readFromStream(stream io.Reader) string {
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(stream)
	return strings.TrimSpace(buf.String())
}

func getUdpAliveTimeout(args *sshArgs, udpProxy bool) time.Duration {
	udpAliveTimeout := getExOptionConfig(args, "UdpAliveTimeout")
	if udpAliveTimeout == "" {
		return getDefaultAliveTimeout(udpProxy)
	}
	timeoutSeconds, err := strconv.Atoi(udpAliveTimeout)
	if err != nil {
		warning("UdpAliveTimeout [%s] invalid: %v", udpAliveTimeout, err)
		return getDefaultAliveTimeout(udpProxy)
	}
	if timeoutSeconds <= 0 && udpProxy {
		warning("UdpAliveTimeout [%d] for proxy invalid", timeoutSeconds)
		return getDefaultAliveTimeout(udpProxy)
	}
	return time.Duration(timeoutSeconds) * time.Second
}

func getDefaultAliveTimeout(udpProxy bool) time.Duration {
	if udpProxy {
		return kDefaultProxyAliveTimeout
	}
	return kDefaultUdpAliveTimeout
}

func getUdpMode(args *sshArgs) int {
	if udpMode := args.Option.get("UdpMode"); udpMode != "" {
		switch strings.ToLower(udpMode) {
		case "no":
			if args.Udp {
				warning("disable UDP since -oUdpMode=No")
			}
			return kUdpModeNo
		case "kcp":
			return kUdpModeKcp
		case "yes", "quic":
			return kUdpModeQuic
		default:
			warning("unknown UdpMode %s", udpMode)
		}
	}

	udpMode := getExConfig(args.Destination, "UdpMode")
	switch strings.ToLower(udpMode) {
	case "", "no":
		break
	case "kcp":
		return kUdpModeKcp
	case "yes", "quic":
		return kUdpModeQuic
	default:
		warning("unknown UdpMode %s", udpMode)
	}

	if args.Udp {
		return kUdpModeQuic
	}
	return kUdpModeNo
}

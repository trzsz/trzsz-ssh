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
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/trzsz/tsshd/tsshd"
	"golang.org/x/crypto/ssh"
)

const kDefaultUdpAliveTimeout = 100 * time.Second

const kDefaultProxyAliveTimeout = 24 * time.Hour

const kDefaultUdpHeartbeatTimeout = 3 * time.Second

const kDefaultUdpReconnectTimeout = 15 * time.Second

type udpModeType int

const (
	kUdpModeNo udpModeType = iota
	kUdpModeYes
	kUdpModeKcp
	kUdpModeQuic
)

func (t udpModeType) String() string {
	return [...]string{
		"No",
		"Yes",
		"KCP",
		"QUIC",
	}[t]
}

type sshUdpClient struct {
	*tsshd.SshUdpClient
	proxyClient      *sshUdpClient
	intervalTime     time.Duration
	aliveTimeout     time.Duration
	connectTimeout   time.Duration
	heartbeatTimeout time.Duration
	reconnectTimeout time.Duration
	lastAliveTime    atomic.Pointer[time.Time]
	udpMainSession   *sshUdpMainSession
	reconnectMutex   sync.Mutex
	reconnectError   atomic.Pointer[error]
	showNotifMutex   sync.Mutex
	showFullNotif    atomic.Bool
	noticeModel      atomic.Pointer[noticeModel]
	noticeOnTop      bool
	neverExit        bool
	exitNotifyChan   chan struct{}
	sshDestName      string
	maxDestLen       int
	offlineFlag      atomic.Bool
}

func (c *sshUdpClient) NewSession() (SshSession, error) {
	return c.SshUdpClient.NewSession()
}
func (c *sshUdpClient) Wait() error {
	if c.neverExit {
		select {}
	}
	return c.SshUdpClient.Wait()
}

func (c *sshUdpClient) exit(code int, cause string) {
	if model := c.noticeModel.Load(); model != nil {
		model.extraMsg = cause
		model.clientExiting.Store(true)
		model.renderView(true, false)
	} else {
		warning("%s", cause)
	}
	close(c.exitNotifyChan)
	c.Exit(code)
}

func (c *sshUdpClient) debug(format string, a ...any) {
	if !enableDebugLogging {
		return
	}
	now := time.Now().Format("15:04:05.000")
	debug(fmt.Sprintf("udp | %s | %-*s | %s", now, c.maxDestLen, c.sshDestName, format), a...)
}

func (c *sshUdpClient) setMainSession(args *sshArgs, mainSession SshSession) SshSession {
	c.noticeOnTop = strings.ToLower(getExOptionConfig(args, "ShowNotificationOnTop")) != "no"
	c.showFullNotif.Store(strings.ToLower(getExOptionConfig(args, "ShowFullNotifications")) != "no")
	c.udpMainSession = &sshUdpMainSession{SshSession: mainSession, udpClient: c}
	if enableDebugLogging {
		c.maxDestLen = len(c.sshDestName)
		client := c
		for client.proxyClient != nil {
			client = client.proxyClient
			c.maxDestLen = max(c.maxDestLen, len(client.sshDestName))
		}
		client = c
		for client.proxyClient != nil {
			client = client.proxyClient
			client.maxDestLen = c.maxDestLen
		}
	}
	return c.udpMainSession
}

func (c *sshUdpClient) isHeartbeatTimeout() bool {
	offline := time.Since(*c.lastAliveTime.Load()) > c.heartbeatTimeout
	if enableDebugLogging {
		if offline {
			if c.offlineFlag.CompareAndSwap(false, true) {
				c.debug("offline for %d seconds", time.Since(*c.lastAliveTime.Load())/time.Second)
			}
		} else {
			if c.offlineFlag.CompareAndSwap(true, false) {
				c.debug("comes back online")
			}
		}
	}
	return offline
}

func (c *sshUdpClient) isReconnectTimeout() bool {
	return time.Since(*c.lastAliveTime.Load()) > c.reconnectTimeout
}

func (c *sshUdpClient) udpKeepAlive(udpProxy bool) {
	c.KeepAlive(c.intervalTime, func() {
		now := time.Now()
		c.lastAliveTime.Store(&now)
	})

	for !c.IsClosed() {
		if time.Since(*c.lastAliveTime.Load()) > c.aliveTimeout {
			c.debug("alive timeout for %v", c.aliveTimeout)
			c.exit(125, fmt.Sprintf("Exit due to connection was lost and timeout for %v", c.aliveTimeout))
			return
		}

		if udpProxy && c.isHeartbeatTimeout() {
			go c.tryToReconnect()
		}

		if c.udpMainSession != nil && c.isReconnectTimeout() {
			go c.showNotifications(udpProxy)
		}

		time.Sleep(c.intervalTime)
	}
}

func (c *sshUdpClient) tryToReconnect() {
	if !c.reconnectMutex.TryLock() {
		return
	}
	defer c.reconnectMutex.Unlock()

	// wait for the proxy to reconnect first
	if c.proxyClient != nil && c.proxyClient.isHeartbeatTimeout() {
		for c.proxyClient.isHeartbeatTimeout() {
			time.Sleep(c.intervalTime)
		}
		time.Sleep(c.heartbeatTimeout)
	}

	if !c.isHeartbeatTimeout() {
		return
	}

	c.debug("try to reconnect")
	if err := c.Reconnect(c.connectTimeout); err != nil {
		c.debug("reconnect failed: %v", err)
		c.reconnectError.Store(&err)
		time.Sleep(c.intervalTime) // don't reconnect too frequently
		return
	}

	c.debug("successfully reconnected")
	c.reconnectError.Store(nil)
	time.Sleep(c.heartbeatTimeout) // give heartbeat some time
}

func (c *sshUdpClient) showNotifications(udpProxy bool) {
	if !c.showNotifMutex.TryLock() {
		return
	}
	defer c.showNotifMutex.Unlock()
	if !c.isReconnectTimeout() {
		return
	}

	intCh := c.udpMainSession.interceptInput()
	defer c.udpMainSession.cancelIntercept()

	c.udpMainSession.curPos = ""
	if c.noticeOnTop {
		fmt.Fprint(os.Stderr, ansi.RequestCursorPositionReport)
		time.Sleep(500 * time.Millisecond)
	}

	model := noticeModel{
		client:      c,
		udpProxy:    udpProxy,
		cursorPos:   c.udpMainSession.curPos,
		borderStyle: lipgloss.NewStyle().BorderStyle(lipgloss.NormalBorder()).BorderForeground(cyanColor).Padding(0, 1, 0, 1),
		statusStyle: lipgloss.NewStyle().Foreground(magentaColor),
		extraStyle:  lipgloss.NewStyle().Foreground(yellowColor),
		errorStyle:  lipgloss.NewStyle().Foreground(lipgloss.Color("240")),
		tipsStyle:   lipgloss.NewStyle().Faint(true),
	}
	c.noticeModel.Store(&model)
	defer c.noticeModel.Store(nil)

	go func() {
		for c.isReconnectTimeout() {
			select {
			case ch, ok := <-intCh:
				c.debug("user input %s", strconv.Quote(string(ch)))
				if !ok {
					return
				}
				switch ch {
				case '\x01': // ctrl + a
					c.showFullNotif.Store(!c.showFullNotif.Load())
				case '\x03': // ctrl + c
					c.exit(126, "Exit due to connection was lost and Ctrl+C was pressed")
					return
				}
			case <-time.After(200 * time.Millisecond):
			}
		}
	}()

	for c.isReconnectTimeout() {
		model.renderView(false, false)
		time.Sleep(200 * time.Millisecond)
	}
	model.renderView(false, true)
	_, _ = doWithTimeout(func() (int, error) {
		c.debug("requesting screen redraw")
		c.udpMainSession.RedrawScreen()
		c.debug("screen redraw completed")
		return 0, nil
	}, c.reconnectTimeout)
	model.renderView(false, false)
}

type noticeModel struct {
	client        *sshUdpClient
	udpProxy      bool
	cursorPos     string
	borderStyle   lipgloss.Style
	statusStyle   lipgloss.Style
	errorStyle    lipgloss.Style
	extraStyle    lipgloss.Style
	tipsStyle     lipgloss.Style
	extraMsg      string
	renderedLines int
	clientExiting atomic.Bool
	renderMutex   sync.Mutex
}

func (m *noticeModel) renderView(exiting, redrawing bool) {
	m.renderMutex.Lock()
	defer m.renderMutex.Unlock()
	if !exiting && m.clientExiting.Load() {
		return
	}
	var buf strings.Builder
	buf.WriteString(ansi.HideCursor)
	if m.cursorPos != "" {
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
	if m.cursorPos != "" {
		buf.WriteString(fmt.Sprintf("\x1b[%sH", m.cursorPos))
		buf.WriteString(ansi.ShowCursor)
	} else if !m.client.isReconnectTimeout() || exiting {
		buf.WriteString(ansi.ShowCursor)
	}
	if exiting {
		buf.WriteString("\r\n")
	}
	m.renderedLines = len(lines)
	fmt.Fprint(os.Stderr, buf.String())
}

func (m *noticeModel) getView(redrawing bool) string {
	if !m.client.isReconnectTimeout() && !redrawing {
		return ""
	}

	var statusMsg string
	if m.clientExiting.Load() {
		statusMsg = m.extraMsg
	} else if redrawing {
		statusMsg = "Congratulations, you have successfully reconnected to the server. The screen is being redrawn, please wait..."
	} else {
		var format string
		if m.udpProxy {
			format = "Oops, looks like the connection to the server was lost, trying to reconnect for %d/%d seconds."
		} else {
			format = "Oops, looks like the connection to the server was lost, automatically exit countdown %d/%d seconds."
		}
		statusMsg = fmt.Sprintf(format, time.Since(*m.client.lastAliveTime.Load())/time.Second, m.client.aliveTimeout/time.Second)
	}

	var buf strings.Builder
	if !m.client.showFullNotif.Load() {
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

func (m *noticeModel) getWidth() int {
	return m.client.udpMainSession.GetTerminalWidth()
}

func (m *noticeModel) getReconnectError() error {
	client := m.client
	for client.proxyClient != nil {
		client = client.proxyClient
	}
	if err := client.reconnectError.Load(); err != nil {
		return *err
	}
	return nil
}

type sshUdpMainSession struct {
	SshSession
	udpClient *sshUdpClient
	intMutex  sync.Mutex
	intFlag   atomic.Bool
	intChan   chan byte
	curPos    string
}

func (s *sshUdpMainSession) interceptInput() <-chan byte {
	s.udpClient.debug("intercepting user input")
	s.intMutex.Lock()
	defer s.intMutex.Unlock()
	if s.intChan == nil {
		s.intChan = make(chan byte, 1)
	}
	s.intFlag.Store(true)
	return s.intChan
}

func (s *sshUdpMainSession) cancelIntercept() {
	s.udpClient.debug("releasing user input")
	s.intMutex.Lock()
	defer s.intMutex.Unlock()
	s.intFlag.Store(false)
}

func (s *sshUdpMainSession) forwardInput(reader io.Reader, writer io.WriteCloser) {
	bufChan := make(chan []byte, 128)
	defer close(bufChan)
	go func() {
		for buf := range bufChan {
			_ = writeAll(writer, buf)
		}
	}()

	buffer := make([]byte, 32*1024)
	for {
		n, err := reader.Read(buffer)
		if s.intFlag.Load() {
			if n == 1 && s.intChan != nil {
				select {
				case s.intChan <- buffer[0]:
				default:
				}
				continue
			}
			if n > 5 && buffer[0] == '\x1b' && buffer[1] == '[' && buffer[n-1] == 'R' { // cursor pos
				s.curPos = string(buffer[2 : n-1])
				continue
			}
			continue
		}
		if n > 0 {
			buf := make([]byte, n)
			copy(buf, buffer[:n])
		out:
			for {
				select {
				case bufChan <- buf:
					break out
				default:
					if s.intFlag.Load() {
						break out
					}
					time.Sleep(100 * time.Millisecond)
				}
			}
		}
		if err != nil {
			break
		}
	}
	if s.intChan != nil {
		close(s.intChan)
	}
}

func (s *sshUdpMainSession) forwardOutput(reader io.Reader, writer io.WriteCloser) {
	defer func() { _ = writer.Close() }()
	buffer := make([]byte, 32*1024)
	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			for s.intFlag.Load() {
				time.Sleep(10 * time.Millisecond)
			}
			_ = writeAll(writer, buffer[:n])
		}
		if err != nil {
			break
		}
	}
}

func (s *sshUdpMainSession) StdinPipe() (io.WriteCloser, error) {
	serverIn, err := s.SshSession.StdinPipe()
	if err != nil {
		return nil, err
	}
	reader, writer := io.Pipe()
	go s.forwardInput(reader, serverIn)
	return writer, nil
}

func (s *sshUdpMainSession) StdoutPipe() (io.Reader, error) {
	serverOut, err := s.SshSession.StdoutPipe()
	if err != nil {
		return nil, err
	}
	reader, writer := io.Pipe()
	go s.forwardOutput(serverOut, writer)
	return reader, nil
}

func (s *sshUdpMainSession) StderrPipe() (io.Reader, error) {
	serverErr, err := s.SshSession.StderrPipe()
	if err != nil {
		return nil, err
	}
	reader, writer := io.Pipe()
	go s.forwardOutput(serverErr, writer)
	return reader, nil
}

func (s *sshUdpMainSession) Close() error {
	return s.doUntilExit(func() error { return s.SshSession.Close() })
}

func (s *sshUdpMainSession) Wait() error {
	return s.doUntilExit(func() error { return s.SshSession.Wait() })
}

func (s *sshUdpMainSession) doUntilExit(task func() error) error {
	done := make(chan error, 1)
	go func() {
		defer close(done)
		err := task()
		done <- err
	}()

	select {
	case <-s.udpClient.exitNotifyChan:
		return nil
	case err := <-done:
		return err
	}
}

var lastJumpUdpClient *sshUdpClient

func udpConnectAsProxy(args *sshArgs, param *sshParam, client SshClient, udpMode udpModeType) (SshClient, error) {
	var err error
	ss := &sshClientSession{client: client, param: param}
	ss.session, err = ss.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("ssh new session failed: %v", err)
	}
	ss.serverOut, err = ss.session.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe failed: %v", err)
	}
	ss.serverErr, err = ss.session.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("stderr pipe failed: %v", err)
	}
	clientSession, err := sshUdpLogin(args, ss, udpMode, true)
	if err != nil {
		return nil, err
	}
	lastJumpUdpClient = clientSession.client.(*sshUdpClient)
	return clientSession.client, nil
}

func sshUdpLogin(args *sshArgs, ss *sshClientSession, udpMode udpModeType, asProxy bool) (*sshClientSession, error) {
	var proxyClient *sshUdpClient
	if ss.param.proxy != nil {
		var ok bool
		proxyClient, ok = ss.param.proxy.client.(*sshUdpClient)
		if !ok {
			warning("There might be a bug. Please raise an issue and post your ProxyJump configuration.")
			return ss, nil
		}
	}
	defer ss.Close()

	debug("udp login to [%s] using UDP mode: %s", args.Destination, udpMode)
	connectTimeout := getConnectTimeout(args)
	udpProxy := strings.ToLower(getExOptionConfig(args, "UdpProxy")) != "no"
	serverInfo, err := startTsshdServer(args, ss, udpMode, udpProxy, connectTimeout)
	if err != nil {
		return nil, fmt.Errorf("udp login to [%s] start tsshd server failed: %v", args.Destination, err)
	}

	var intervalTime time.Duration
	aliveTimeout := getUdpTimeoutConfig(args, "UdpAliveTimeout", getDefaultAliveTimeout(udpProxy))
	heartbeatTimeout := getUdpTimeoutConfig(args, "UdpHeartbeatTimeout", kDefaultUdpHeartbeatTimeout)
	reconnectTimeout := getUdpTimeoutConfig(args, "UdpReconnectTimeout", kDefaultUdpReconnectTimeout)
	if udpProxy {
		intervalTime = min(aliveTimeout/10, min(heartbeatTimeout, reconnectTimeout)/5, 1*time.Second)
	} else {
		intervalTime = min(aliveTimeout/10, 10*time.Second)
	}

	tsshdAddr := joinHostPort(ss.param.host, strconv.Itoa(serverInfo.Port))
	debug("udp login to [%s] tsshd server addr: %s", args.Destination, tsshdAddr)
	if ss.param.proxy != nil && proxyClient != nil {
		localAddr, err := proxyClient.ForwardUDPv1(tsshdAddr, max(connectTimeout, heartbeatTimeout, reconnectTimeout))
		if err != nil {
			return nil, fmt.Errorf("udp login to [%s] forward udp [%s] failed: %v", args.Destination, tsshdAddr, err)
		}
		debug("udp login to [%s] proxy jump: %s <=> [%s] <=> %s", args.Destination, localAddr, ss.param.proxy.name, tsshdAddr)
		tsshdAddr = localAddr
	}

	client, err := tsshd.NewSshUdpClient(tsshdAddr, serverInfo, connectTimeout, aliveTimeout, intervalTime, warning)
	if err != nil {
		return nil, fmt.Errorf("udp login to [%s] failed: %v", args.Destination, err)
	}
	debug("udp login to [%s] success", args.Destination)

	udpClient := sshUdpClient{
		SshUdpClient:     client,
		proxyClient:      proxyClient,
		intervalTime:     intervalTime,
		aliveTimeout:     aliveTimeout,
		connectTimeout:   connectTimeout,
		heartbeatTimeout: heartbeatTimeout,
		reconnectTimeout: reconnectTimeout,
		exitNotifyChan:   make(chan struct{}),
		sshDestName:      args.Destination,
	}

	// keep alive
	now := time.Now()
	udpClient.lastAliveTime.Store(&now)
	go udpClient.udpKeepAlive(udpProxy)

	if asProxy {
		return &sshClientSession{client: &udpClient}, nil
	}

	// no exit while not executing remote command or running in background
	if args.NoCommand || args.Background {
		udpClient.neverExit = true
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
		_ = client.Close()
		return nil, fmt.Errorf("udp login to [%s] new session failed: %v", args.Destination, err)
	}
	udpSession = udpClient.setMainSession(args, udpSession)

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

func startTsshdServer(args *sshArgs, ss *sshClientSession, udpMode udpModeType, udpProxy bool,
	connectTimeout time.Duration) (*tsshd.ServerInfo, error) {
	cmd := getTsshdCommand(args, udpMode, udpProxy, connectTimeout)
	debug("udp login to [%s] tsshd command: %s", args.Destination, cmd)

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

func getTsshdCommand(args *sshArgs, udpMode udpModeType, udpProxy bool, connectTimeout time.Duration) string {
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
	network := getNetworkAddressFamily(args)
	if strings.HasSuffix(network, "4") {
		buf.WriteString(" --ipv4")
	}
	if strings.HasSuffix(network, "6") {
		buf.WriteString(" --ipv6")
	}
	if connectTimeout != kDefaultConnectTimeout {
		buf.WriteString(" --connect-timeout ")
		buf.WriteString(strconv.Itoa(int(connectTimeout / time.Second)))
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
			func() {
				lowPort, err := strconv.Atoi(ports[0])
				if err != nil {
					warning("UdpPort %s is invalid: %v", udpPort, err)
					return
				}
				highPort, err := strconv.Atoi(ports[1])
				if err != nil {
					warning("UdpPort %s is invalid: %v", udpPort, err)
					return
				}
				buf.WriteString(fmt.Sprintf(" --port %d-%d", lowPort, highPort))
			}()
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

func getUdpTimeoutConfig(args *sshArgs, timeoutOption string, defaultTimeout time.Duration) time.Duration {
	timeoutConfig := getExOptionConfig(args, timeoutOption)
	if timeoutConfig == "" {
		return defaultTimeout
	}
	timeoutSeconds, err := strconv.Atoi(timeoutConfig)
	if err != nil {
		warning("%s [%s] invalid: %v", timeoutOption, timeoutConfig, err)
		return defaultTimeout
	}
	if timeoutSeconds <= 0 {
		warning("%s [%d] <= 0 is not supported", timeoutOption, timeoutSeconds)
		return defaultTimeout
	}
	return time.Duration(timeoutSeconds) * time.Second
}

func getDefaultAliveTimeout(udpProxy bool) time.Duration {
	if udpProxy {
		return kDefaultProxyAliveTimeout
	}
	return kDefaultUdpAliveTimeout
}

func getUdpMode(args *sshArgs) udpModeType {
	if udpMode := args.Option.get("UdpMode"); udpMode != "" {
		switch strings.ToLower(udpMode) {
		case "no":
			if args.Udp {
				warning("disable UDP since -oUdpMode=No")
			}
			return kUdpModeNo
		case "yes":
			return kUdpModeYes
		case "kcp":
			return kUdpModeKcp
		case "quic":
			return kUdpModeQuic
		default:
			warning("unknown UdpMode %s", udpMode)
		}
	}

	udpMode := getExConfig(args.Destination, "UdpMode")
	switch strings.ToLower(udpMode) {
	case "", "no":
		break
	case "yes":
		return kUdpModeYes
	case "kcp":
		return kUdpModeKcp
	case "quic":
		return kUdpModeQuic
	default:
		warning("unknown UdpMode %s", udpMode)
	}

	if args.Udp {
		return kUdpModeYes
	}
	return kUdpModeNo
}

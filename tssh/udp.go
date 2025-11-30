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
	waitCloseChan    chan struct{}
	lastAliveTime    atomic.Int64
	udpMainSession   *sshUdpMainSession
	reconnectMutex   sync.Mutex
	reconnectError   atomic.Pointer[error]
	showNotifMutex   sync.Mutex
	showFullNotif    atomic.Bool
	noticeModel      atomic.Pointer[noticeModel]
	noticeOnTop      bool
	sshDestName      string
	maxDestLen       int
	offlineFlag      atomic.Bool
	sshConn          *sshConnection
}

func (c *sshUdpClient) NewSession() (SshSession, error) {
	return c.SshUdpClient.NewSession()
}

func (c *sshUdpClient) Close() error {
	err := c.SshUdpClient.Close()
	if c.waitCloseChan != nil {
		select {
		case c.waitCloseChan <- struct{}{}:
		default:
		}
	}
	return err
}

func (c *sshUdpClient) Wait() error {
	if c.waitCloseChan != nil {
		<-c.waitCloseChan
	}
	return c.SshUdpClient.Wait()
}

func (c *sshUdpClient) exit(code int, cause string) {
	if model := c.noticeModel.Load(); model != nil {
		model.clientExiting.Store(true)
		model.renderView(true, false)
	}
	c.sshConn.forceExit(code, cause)
}

func (c *sshUdpClient) debug(format string, a ...any) {
	if !enableDebugLogging {
		return
	}
	msg := fmt.Sprintf(format, a...)
	now := time.Now().Format("15:04:05.000")
	debug("udp | %s | %-*s | %s", now, c.maxDestLen, c.sshDestName, msg)
}

func (c *sshUdpClient) setMainSession(sshConn *sshConnection) {
	if isTerminal && sshConn.tty {
		c.noticeOnTop = strings.ToLower(getExOptionConfig(sshConn.param.args, "ShowNotificationOnTop")) != "no"
		c.showFullNotif.Store(strings.ToLower(getExOptionConfig(sshConn.param.args, "ShowFullNotifications")) != "no")
		c.udpMainSession = &sshUdpMainSession{SshSession: sshConn.session, udpClient: c}
		sshConn.session = c.udpMainSession
	}

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
}

func (c *sshUdpClient) isHeartbeatTimeout() bool {
	offline := time.Since(time.UnixMilli(c.lastAliveTime.Load())) > c.heartbeatTimeout
	if enableDebugLogging {
		if offline {
			if c.offlineFlag.CompareAndSwap(false, true) {
				c.debug("offline for %d milliseconds", time.Since(time.UnixMilli(c.lastAliveTime.Load()))/time.Millisecond)
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
	return time.Since(time.UnixMilli(c.lastAliveTime.Load())) > c.reconnectTimeout
}

func (c *sshUdpClient) udpKeepAlive(udpProxy bool) {
	ackChan := make(chan int64, 2) // do not close to prevent writing after closing
	aliveCallback := func(aliveTime int64) {
		if c.IsClosed() {
			return
		}

		if aliveTime == 0 {
			if enableDebugLogging && c.isHeartbeatTimeout() {
				c.debug("received ping response from the server")
			}
			c.lastAliveTime.Store(time.Now().UnixMilli())
			select {
			case ackChan <- 0:
			default:
			}
			return
		}

		if enableDebugLogging && c.isHeartbeatTimeout() {
			c.debug("keep alive response [%d]: %v", aliveTime, time.UnixMilli(aliveTime).Format("15:04:05.000"))
		}
		c.lastAliveTime.Store(aliveTime)
		ackChan <- aliveTime
	}

	ticker := time.NewTicker(c.intervalTime)
	defer ticker.Stop()
	go func() {
		for range ticker.C {
			aliveTime := time.Now().UnixMilli()
			if enableDebugLogging && c.isHeartbeatTimeout() {
				c.debug("begin to send keep alive [%d]", aliveTime)
			}
			err := c.KeepAlive(aliveTime, aliveCallback)
			if err != nil {
				warning("udp [%s] keep alive failed: %v", c.sshDestName, err)
			}
			if enableDebugLogging && c.isHeartbeatTimeout() {
				c.debug("send keep alive [%d] complete: %v", aliveTime, err)
			}
			for {
				ackAliveTime := <-ackChan
				if ackAliveTime == aliveTime || ackAliveTime == 0 {
					break
				}
			}
		}
	}()

	for !c.IsClosed() {
		if c.sshConn != nil && time.Since(time.UnixMilli(c.lastAliveTime.Load())) > c.aliveTimeout {
			c.debug("alive timeout for %v", c.aliveTimeout)
			c.exit(kExitCodeUdpTimeout, fmt.Sprintf("Exit due to connection was lost and timeout for %v", c.aliveTimeout))
			return
		}

		if udpProxy && c.isHeartbeatTimeout() {
			go c.tryToReconnect()
		}

		if isTerminal && enableWarningLogging && c.sshConn != nil && c.isReconnectTimeout() {
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

func (c *sshUdpClient) getConnLostStatus(udpProxy bool) string {
	var format string
	if udpProxy {
		format = "Oops, looks like the connection to the server was lost, trying to reconnect for %d/%d seconds."
	} else {
		format = "Oops, looks like the connection to the server was lost, automatically exit countdown %d/%d seconds."
	}
	return fmt.Sprintf(format, time.Since(time.UnixMilli(c.lastAliveTime.Load()))/time.Second, c.aliveTimeout/time.Second)
}

func (c *sshUdpClient) showNotifications(udpProxy bool) {
	if !c.showNotifMutex.TryLock() {
		return
	}
	defer c.showNotifMutex.Unlock()
	if !c.isReconnectTimeout() {
		return
	}

	if c.udpMainSession == nil {
		fmt.Fprintf(os.Stderr, ansi.HideCursor)
		for c.isReconnectTimeout() && !c.sshConn.exited.Load() {
			fmt.Fprintf(os.Stderr, "\r\033[0;33m%s\033[0m\x1b[K", c.getConnLostStatus(udpProxy))
			time.Sleep(time.Second)
		}
		if !c.isReconnectTimeout() && !c.sshConn.exited.Load() {
			fmt.Fprintf(os.Stderr, "\r\033[0;32m%s\033[0m\x1b[K\r\n", "Congratulations, you have successfully reconnected to the server.")
		}
		fmt.Fprintf(os.Stderr, ansi.ShowCursor)
		return
	}

	intCh := c.udpMainSession.interceptInput()
	defer c.udpMainSession.cancelIntercept()

	c.udpMainSession.curPos.Store(nil)
	if c.noticeOnTop {
		fmt.Fprint(os.Stderr, ansi.RequestCursorPositionReport)
		for range 50 {
			time.Sleep(10 * time.Millisecond)
			if c.udpMainSession.curPos.Load() != nil {
				break
			}
		}
	}

	model := noticeModel{
		client:      c,
		udpProxy:    udpProxy,
		cursorPos:   c.udpMainSession.curPos.Load(),
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
				c.debug("user input %s", strconv.QuoteToASCII(string(ch)))
				if !ok {
					return
				}
				switch ch {
				case '\x01': // ctrl + a
					c.showFullNotif.Store(!c.showFullNotif.Load())
				case '\x03': // ctrl + c
					c.exit(kExitCodeUdpCtrlC, "Exit due to connection was lost and Ctrl+C was pressed")
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
	cursorPos     *string
	borderStyle   lipgloss.Style
	statusStyle   lipgloss.Style
	errorStyle    lipgloss.Style
	extraStyle    lipgloss.Style
	tipsStyle     lipgloss.Style
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
	if m.client.noticeOnTop {
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
	if m.client.noticeOnTop {
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
	fmt.Fprint(os.Stderr, buf.String())
}

func (m *noticeModel) getView(redrawing bool) string {
	if !m.client.isReconnectTimeout() && !redrawing || m.clientExiting.Load() {
		return ""
	}

	var statusMsg string
	if redrawing {
		statusMsg = "Congratulations, you have successfully reconnected to the server. The screen is being redrawn, please wait..."
	} else {
		statusMsg = m.client.getConnLostStatus(m.udpProxy)
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

type sshUdpMainSession struct {
	SshSession
	udpClient *sshUdpClient
	waitGroup sync.WaitGroup
	intMutex  sync.Mutex
	intFlag   atomic.Bool
	intChan   chan byte
	curPos    atomic.Pointer[string]
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
		defer func() { _ = writer.Close() }()
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
				curPos := string(buffer[2 : n-1])
				s.curPos.Store(&curPos)
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
	s.waitGroup.Go(func() { s.forwardOutput(serverOut, writer) })
	return reader, nil
}

func (s *sshUdpMainSession) StderrPipe() (io.Reader, error) {
	serverErr, err := s.SshSession.StderrPipe()
	if err != nil {
		return nil, err
	}
	reader, writer := io.Pipe()
	s.waitGroup.Go(func() { s.forwardOutput(serverErr, writer) })
	return reader, nil
}

var lastJumpUdpClient *sshUdpClient
var globalUdpAliveTimeout time.Duration

func quitCallback(reason string) {
	for lastJumpUdpClient == nil || lastJumpUdpClient.sshConn == nil {
		time.Sleep(10 * time.Millisecond) // waiting for sshConn to be initialized
	}
	lastJumpUdpClient.sshConn.forceExit(kExitCodeSignalKill, fmt.Sprintf("Exit due to %s", reason))
}

func initGlobalUdpAliveTimeout(args *sshArgs) {
	if globalUdpAliveTimeout != 0 {
		warning("global udp alive timeout [%v] has already been initialized", globalUdpAliveTimeout)
		return
	}
	udpProxy := strings.ToLower(getExOptionConfig(args, "UdpProxy")) != "no"
	globalUdpAliveTimeout = getUdpTimeoutConfig(args, "UdpAliveTimeout", getDefaultAliveTimeout(udpProxy))
	debug("init global udp alive timeout [%v] for [%s]", globalUdpAliveTimeout, args.Destination)
}

func udpLogin(param *sshParam, tcpClient SshClient) (SshClient, error) {
	defer func() { _ = tcpClient.Close() }()
	args := param.args
	debug("udp login to [%s] using UDP mode: %s", args.Destination, param.udpMode)

	// start tsshd
	connectTimeout := getConnectTimeout(args)
	udpProxy := strings.ToLower(getExOptionConfig(args, "UdpProxy")) != "no"
	tsshdCmd := getTsshdCommand(param, udpProxy, connectTimeout)
	debug("udp login to [%s] tsshd command: %s", args.Destination, tsshdCmd)

	serverInfo, err := startTsshdServer(tcpClient, tsshdCmd)
	if err != nil {
		return nil, fmt.Errorf("udp login to [%s] start tsshd failed: %v", args.Destination, err)
	}

	// udp config
	if globalUdpAliveTimeout == 0 {
		warning("global udp alive timeout for [%s] has not been initialized yet", args.Destination)
		initGlobalUdpAliveTimeout(param.args)
	}
	heartbeatTimeout := getUdpTimeoutConfig(args, "UdpHeartbeatTimeout", kDefaultUdpHeartbeatTimeout)
	reconnectTimeout := getUdpTimeoutConfig(args, "UdpReconnectTimeout", kDefaultUdpReconnectTimeout)
	var intervalTime time.Duration
	if udpProxy {
		intervalTime = min(globalUdpAliveTimeout/10, min(heartbeatTimeout, reconnectTimeout)/5, 1*time.Second)
	} else {
		intervalTime = min(globalUdpAliveTimeout/10, 10*time.Second)
	}

	tsshdAddr := joinHostPort(param.host, strconv.Itoa(serverInfo.Port))
	if param.ipv4 {
		addr, err := net.ResolveUDPAddr("udp4", tsshdAddr)
		if err != nil {
			warning("resolve [udp4] addr [%s] failed: %v", tsshdAddr, err)
		} else {
			debug("udp login to [%s] tsshd server addr: %s => %s", param.args.Destination, tsshdAddr, addr)
			tsshdAddr = addr.String()
		}
	} else if param.ipv6 {
		addr, err := net.ResolveUDPAddr("udp6", tsshdAddr)
		if err != nil {
			warning("resolve [udp6] addr [%s] failed: %v", tsshdAddr, err)
		} else {
			debug("udp login to [%s] tsshd server addr: %s => %s", param.args.Destination, tsshdAddr, addr)
			tsshdAddr = addr.String()
		}
	} else {
		debug("udp login to [%s] tsshd server addr: %s", param.args.Destination, tsshdAddr)
	}

	// proxy forward
	var proxyClient *sshUdpClient
	if param.proxy != nil {
		var ok bool
		proxyClient, ok = param.proxy.client.(*sshUdpClient)
		if !ok {
			return nil, fmt.Errorf("proxy client [%T] for [%s] is not a udp client", param.proxy.client, args.Destination)
		}
		localAddr, err := proxyClient.ForwardUDPv1(tsshdAddr, max(connectTimeout, heartbeatTimeout, reconnectTimeout))
		if err != nil {
			return nil, fmt.Errorf("udp login to [%s] forward udp [%s] failed: %v", args.Destination, tsshdAddr, err)
		}
		debug("udp login to [%s] proxy jump: %s <=> [%s] <=> %s", args.Destination, localAddr, param.proxy.name, tsshdAddr)
		tsshdAddr = localAddr
	}

	// new udp client
	client, err := tsshd.NewSshUdpClient(tsshdAddr, serverInfo, connectTimeout, globalUdpAliveTimeout, intervalTime, quitCallback)
	if err != nil {
		return nil, fmt.Errorf("udp login to [%s] failed: %v", args.Destination, err)
	}
	if enableDebugLogging {
		client.SetDebugFunc(args.Destination, debug)
	}
	if enableWarningLogging {
		client.SetWarningFunc(warning)
	}
	debug("udp login to [%s] success", args.Destination)

	udpClient := &sshUdpClient{
		SshUdpClient:     client,
		proxyClient:      proxyClient,
		intervalTime:     intervalTime,
		aliveTimeout:     globalUdpAliveTimeout,
		connectTimeout:   connectTimeout,
		heartbeatTimeout: heartbeatTimeout,
		reconnectTimeout: reconnectTimeout,
		sshDestName:      args.Destination,
	}

	lastJumpUdpClient = udpClient

	// preventing exit for just forwarding ports
	if args.NoCommand || args.Background {
		udpClient.waitCloseChan = make(chan struct{}, 1)
	}

	// udp keep alive
	udpClient.lastAliveTime.Store(time.Now().UnixMilli())
	go udpClient.udpKeepAlive(udpProxy)

	return udpClient, nil
}

func startTsshdServer(tcpClient SshClient, tsshdCmd string) (*tsshd.ServerInfo, error) {
	session, err := tcpClient.NewSession()
	if err != nil {
		return nil, fmt.Errorf("new session failed: %v", err)
	}
	defer func() { _ = session.Close() }()
	serverOut, err := session.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe failed: %v", err)
	}
	serverErr, err := session.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("stderr pipe failed: %v", err)
	}
	if err := session.RequestPty("xterm-256color", 200, 800, ssh.TerminalModes{}); err != nil {
		return nil, fmt.Errorf("request pty for tsshd failed: %v", err)
	}

	if err := session.Start(tsshdCmd); err != nil {
		return nil, fmt.Errorf("start tsshd failed: %v", err)
	}
	if err := session.Wait(); err != nil {
		var builder strings.Builder
		if outMsg := readFromStream(serverOut); outMsg != "" {
			builder.WriteString(outMsg)
		}
		if errMsg := readFromStream(serverErr); errMsg != "" {
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

	output := readFromStream(serverOut)
	if output == "" {
		if errMsg := readFromStream(serverErr); errMsg != "" {
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

func getTsshdCommand(param *sshParam, udpProxy bool, connectTimeout time.Duration) string {
	args := param.args
	var buf strings.Builder
	if args.TsshdPath != "" {
		buf.WriteString(args.TsshdPath)
	} else if tsshdPath := getExOptionConfig(args, "TsshdPath"); tsshdPath != "" {
		buf.WriteString(tsshdPath)
	} else {
		buf.WriteString("tsshd")
	}

	if param.udpMode == kUdpModeKcp {
		buf.WriteString(" --kcp")
	}
	if udpProxy {
		buf.WriteString(" --proxy")
	}
	if enableDebugLogging {
		buf.WriteString(" --debug")
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
			port, err := strconv.ParseUint(ports[0], 10, 16)
			if err != nil {
				warning("UdpPort %s is invalid: %v", udpPort, err)
			} else {
				buf.WriteString(fmt.Sprintf(" --port %d", port))
			}
		} else if len(ports) == 2 {
			func() {
				lowPort, err := strconv.ParseUint(ports[0], 10, 16)
				if err != nil {
					warning("UdpPort %s is invalid: %v", udpPort, err)
					return
				}
				highPort, err := strconv.ParseUint(ports[1], 10, 16)
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
	timeoutSeconds, err := strconv.ParseUint(timeoutConfig, 10, 32)
	if err != nil {
		warning("%s [%s] invalid: %v", timeoutOption, timeoutConfig, err)
		return defaultTimeout
	}
	if timeoutSeconds <= 0 {
		warning("%s [%d] must be greater than 0", timeoutOption, timeoutSeconds)
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

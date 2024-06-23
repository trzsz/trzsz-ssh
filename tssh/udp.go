/*
MIT License

Copyright (c) 2023-2024 The Trzsz SSH Authors.

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
	"crypto/sha1"
	"encoding/hex"
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

	"github.com/google/shlex"
	"github.com/trzsz/tsshd/tsshd"
	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ssh"
)

const kDefaultUdpAliveTimeout = 100 * time.Second

type sshUdpClient struct {
	key           []byte
	addr          string
	wg            sync.WaitGroup
	busMutex      sync.Mutex
	busSession    *kcp.UDPSession
	sessionMutex  sync.Mutex
	sessionID     atomic.Uint64
	sessionMap    map[uint64]*sshUdpSession
	lastAliveTime atomic.Pointer[time.Time]
	closed        atomic.Bool
}

func (c *sshUdpClient) Wait() error {
	c.wg.Wait()
	return nil
}

func (c *sshUdpClient) Close() error {
	c.busMutex.Lock()
	defer c.busMutex.Unlock()
	if err := tsshd.SendCommand(c.busSession, "close"); err != nil {
		warning("send close command failed: %v", err)
	}
	c.closed.Store(true)
	return c.busSession.Close()
}

func (c *sshUdpClient) NewSession() (sshSession, error) {
	kcpSession, err := newKcpSession(c.addr, c.key, "session")
	if err != nil {
		return nil, err
	}
	c.wg.Add(1)
	udpSession := &sshUdpSession{client: c, session: kcpSession, envs: make(map[string]string)}
	udpSession.wg.Add(1)
	c.sessionMutex.Lock()
	defer c.sessionMutex.Unlock()
	udpSession.id = c.sessionID.Add(1) - 1
	c.sessionMap[udpSession.id] = udpSession
	return udpSession, nil
}

func (c *sshUdpClient) DialTimeout(network, addr string, timeout time.Duration) (net.Conn, error) {
	session, err := newKcpSession(c.addr, c.key, "dial")
	if err != nil {
		return nil, err
	}
	msg := tsshd.DialMessage{
		Network: network,
		Addr:    addr,
		Timeout: timeout,
	}
	if err := tsshd.SendMessage(session, &msg); err != nil {
		session.Close()
		return nil, fmt.Errorf("send dial message failed: %v", err)
	}
	if err := tsshd.RecvError(session); err != nil {
		session.Close()
		return nil, err
	}
	c.wg.Add(1)
	return &sshUdpConn{session, c}, nil
}

func (c *sshUdpClient) Listen(network, addr string) (net.Listener, error) {
	session, err := newKcpSession(c.addr, c.key, "listen")
	if err != nil {
		return nil, err
	}
	msg := tsshd.ListenMessage{
		Network: network,
		Addr:    addr,
	}
	if err := tsshd.SendMessage(session, &msg); err != nil {
		session.Close()
		return nil, fmt.Errorf("send listen message failed: %v", err)
	}
	if err := tsshd.RecvError(session); err != nil {
		session.Close()
		return nil, err
	}
	c.wg.Add(1)
	return &sshUdpListener{client: c, session: session}, nil
}

func (c *sshUdpClient) HandleChannelOpen(channelType string) <-chan ssh.NewChannel {
	return nil
}

func (c *sshUdpClient) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	return false, nil, fmt.Errorf("ssh udp client SendRequest is not supported yet")
}

func (c *sshUdpClient) sendBusCommand(command string) error {
	c.busMutex.Lock()
	defer c.busMutex.Unlock()
	return tsshd.SendCommand(c.busSession, command)
}

func (c *sshUdpClient) sendBusMessage(command string, msg any) error {
	c.busMutex.Lock()
	defer c.busMutex.Unlock()
	if err := tsshd.SendCommand(c.busSession, command); err != nil {
		return err
	}
	return tsshd.SendMessage(c.busSession, msg)
}

func (c *sshUdpClient) udpKeepAlive(timeout time.Duration) {
	for {
		if err := c.sendBusCommand("alive"); err != nil {
			warning("udp keep alive failed: %v", err)
		}
		if t := c.lastAliveTime.Load(); t != nil && time.Since(*t) > timeout {
			warning("udp keep alive timeout")
			os.Exit(125)
		}
		time.Sleep(timeout / 10)
		if c.closed.Load() {
			return
		}
	}
}

func (c *sshUdpClient) handleBusEvent() {
	for {
		command, err := tsshd.RecvCommand(c.busSession)
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
		case "alive":
			now := time.Now()
			c.lastAliveTime.Store(&now)
		default:
			warning("unknown command bus command: %s", command)
		}
	}
}

func (c *sshUdpClient) handleExitEvent() {
	var exitMsg tsshd.ExitMessage
	if err := tsshd.RecvMessage(c.busSession, &exitMsg); err != nil {
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
	udpSession.code = exitMsg.ExitCode
	udpSession.wg.Done()
	// the kcp server does not send io.EOF, we trigger it ourselves.
	if udpSession.stdout != nil {
		udpSession.stdout.Close()
	}
	if udpSession.stderr != nil {
		udpSession.stderr.Close()
	}

	delete(c.sessionMap, exitMsg.ID)
	c.wg.Done()
}

func (c *sshUdpClient) handleErrorEvent() {
	var errMsg tsshd.ErrorMessage
	if err := tsshd.RecvMessage(c.busSession, &errMsg); err != nil {
		warning("recv error message failed: %v", err)
		return
	}
	warning("udp error: %s", errMsg.Msg)
}

type sshUdpSession struct {
	id      uint64
	wg      sync.WaitGroup
	client  *sshUdpClient
	session *kcp.UDPSession
	pty     bool
	height  int
	width   int
	envs    map[string]string
	started bool
	stdin   io.Reader
	stdout  io.WriteCloser
	stderr  *kcp.UDPSession
	code    int
}

func (s *sshUdpSession) Wait() error {
	s.wg.Wait()
	if s.code != 0 {
		return fmt.Errorf("udp session exit with %d", s.code)
	}
	return nil
}

func (s *sshUdpSession) Close() error {
	if s.stdout != nil {
		_ = s.stdout.Close()
	}
	if s.stderr != nil {
		_ = s.stderr.Close()
	}
	return s.session.Close()
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

func (s *sshUdpSession) startSession(msg *tsshd.StartMessage) error {
	if s.started {
		return fmt.Errorf("session already started")
	}
	s.started = true
	if err := tsshd.SendMessage(s.session, msg); err != nil {
		return fmt.Errorf("send session message failed: %v", err)
	}
	if err := tsshd.RecvError(s.session); err != nil {
		return err
	}
	if s.stdin != nil {
		go func() {
			_, _ = io.Copy(s.session, s.stdin)
		}()
	}
	if s.stdout != nil {
		go func() {
			defer s.stdout.Close()
			_, _ = io.Copy(s.stdout, s.session)
		}()
	}
	return nil
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
	session, err := newKcpSession(s.client.addr, s.client.key, "stderr")
	if err != nil {
		return nil, err
	}
	if err := tsshd.SendMessage(session, tsshd.StderrMessage{ID: s.id}); err != nil {
		session.Close()
		return nil, fmt.Errorf("send stderr message failed: %v", err)
	}
	if err := tsshd.RecvError(session); err != nil {
		session.Close()
		return nil, err
	}
	s.stderr = session
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
	return false, fmt.Errorf("ssh udp session SendRequest is not supported yet")
}

type sshUdpListener struct {
	client  *sshUdpClient
	session *kcp.UDPSession
}

func (l *sshUdpListener) Accept() (net.Conn, error) {
	var msg tsshd.AcceptMessage
	if err := tsshd.RecvMessage(l.session, &msg); err != nil {
		return nil, fmt.Errorf("recv accept message failed: %v", err)
	}
	session, err := newKcpSession(l.client.addr, l.client.key, "accept")
	if err != nil {
		return nil, err
	}
	if err := tsshd.SendMessage(session, &msg); err != nil {
		session.Close()
		return nil, fmt.Errorf("send accept message failed: %v", err)
	}
	if err := tsshd.RecvError(session); err != nil {
		session.Close()
		return nil, err
	}
	l.client.wg.Add(1)
	return &sshUdpConn{session, l.client}, nil
}

func (l *sshUdpListener) Close() error {
	l.client.wg.Done()
	return l.session.Close()
}

func (l *sshUdpListener) Addr() net.Addr {
	return nil
}

type sshUdpConn struct {
	*kcp.UDPSession
	client *sshUdpClient
}

func (c *sshUdpConn) Close() error {
	c.client.wg.Done()
	return c.UDPSession.Close()
}

func sshUdpLogin(args *sshArgs, param *sshParam, ss *sshClientSession) (*sshClientSession, error) {
	defer ss.Close()

	svrInfo, err := startTsshdServer(args, ss)
	if err != nil {
		return nil, err
	}
	pass, err := hex.DecodeString(svrInfo.Pass)
	if err != nil {
		return nil, fmt.Errorf("decode pass [%s] failed: %v", svrInfo.Pass, err)
	}
	salt, err := hex.DecodeString(svrInfo.Salt)
	if err != nil {
		return nil, fmt.Errorf("decode salt [%s] failed: %v", svrInfo.Pass, err)
	}
	key := pbkdf2.Key(pass, salt, 4096, 32, sha1.New)
	addr := joinHostPort(param.host, strconv.Itoa(svrInfo.Port))

	busSession, err := newKcpSession(addr, key, "bus")
	if err != nil {
		return nil, err
	}

	udpAliveTimeout := getUdpAliveTimeout(args)
	if err := tsshd.SendMessage(busSession, tsshd.BusMessage{Timeout: udpAliveTimeout}); err != nil {
		busSession.Close()
		return nil, fmt.Errorf("send bus message failed: %v", err)
	}
	if err := tsshd.RecvError(busSession); err != nil {
		busSession.Close()
		return nil, err
	}

	debug("udp login [%s] success", args.Destination)
	udpClient := sshUdpClient{
		key:        key,
		addr:       addr,
		busSession: busSession,
		sessionMap: make(map[uint64]*sshUdpSession),
	}

	// keep alive
	if udpAliveTimeout > 0 {
		now := time.Now()
		udpClient.lastAliveTime.Store(&now)
		go udpClient.udpKeepAlive(udpAliveTimeout)
	}

	go udpClient.handleBusEvent()

	// no exit while not executing remote command or running in background
	if args.NoCommand || args.Background {
		udpClient.wg.Add(1)
	}

	// if running as a proxy ( aka: stdio forward ), or if not executing remote command,
	// then there is no need to make a new session, so we return early here.
	if args.StdioForward != "" || args.NoCommand {
		return &sshClientSession{
			client: &udpClient,
			cmd:    ss.cmd,
			tty:    ss.tty,
		}, nil
	}

	udpSession, err := udpClient.NewSession()
	if err != nil {
		busSession.Close()
		return nil, fmt.Errorf("new session failed: %v", err)
	}

	serverIn, _ := udpSession.StdinPipe()
	serverOut, _ := udpSession.StdoutPipe()
	return &sshClientSession{
		client:    &udpClient,
		session:   udpSession,
		serverIn:  serverIn,
		serverOut: serverOut,
		serverErr: nil,
		cmd:       ss.cmd,
		tty:       ss.tty,
	}, nil
}

func startTsshdServer(args *sshArgs, ss *sshClientSession) (*tsshd.ServerInfo, error) {
	cmd := getTsshdCommand(args)
	debug("tsshd command: %s", cmd)

	if err := ss.session.RequestPty("xterm-256color", 20, 80, ssh.TerminalModes{}); err != nil {
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
	pos := strings.LastIndex(output, "\a{")
	if pos >= 0 {
		output = output[pos+1:]
	}
	if !strings.HasPrefix(output, "{") || !strings.HasSuffix(output, "}") {
		return nil, fmt.Errorf("run tsshd failed: %s", output)
	}

	var svrInfo tsshd.ServerInfo
	if err := json.Unmarshal([]byte(output), &svrInfo); err != nil {
		return nil, fmt.Errorf("json unmarshal [%s] failed: %v", output, err)
	}

	return &svrInfo, nil
}

func getTsshdCommand(args *sshArgs) string {
	var buf strings.Builder
	if args.TsshdPath != "" {
		buf.WriteString(args.TsshdPath)
	} else if tsshdPath := getExOptionConfig(args, "TsshdPath"); tsshdPath != "" {
		buf.WriteString(tsshdPath)
	} else {
		buf.WriteString("tsshd")
	}
	return buf.String()
}

func readFromStream(stream io.Reader) string {
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(stream)
	return strings.TrimSpace(buf.String())
}

func newKcpSession(addr string, key []byte, cmd string) (session *kcp.UDPSession, err error) {
	block, err := kcp.NewAESBlockCrypt(key)
	if err != nil {
		return nil, fmt.Errorf("new aes block crypt failed: %v", err)
	}

	done := make(chan struct{}, 1)
	go func() {
		defer func() {
			if err != nil && session != nil {
				session.Close()
			}
			done <- struct{}{}
			close(done)
		}()
		session, err = kcp.DialWithOptions(addr, block, 10, 3)
		if err != nil {
			err = fmt.Errorf("kcp dial [%s] [%s] failed: %v", addr, cmd, err)
			return
		}
		if err = tsshd.SendCommand(session, cmd); err != nil {
			err = fmt.Errorf("kcp send command [%s] [%s] failed: %v", addr, cmd, err)
			return
		}
		if err = tsshd.RecvError(session); err != nil {
			err = fmt.Errorf("kcp new session [%s] [%s] failed: %v", addr, cmd, err)
			return
		}
	}()

	select {
	case <-time.After(10 * time.Second):
		err = fmt.Errorf("kcp new session [%s] [%s] timeout", addr, cmd)
	case <-done:
	}
	return
}

func getUdpAliveTimeout(args *sshArgs) time.Duration {
	udpAliveTimeout := getExOptionConfig(args, "UdpAliveTimeout")
	if udpAliveTimeout == "" {
		return kDefaultUdpAliveTimeout
	}
	timeoutSeconds, err := strconv.Atoi(udpAliveTimeout)
	if err != nil {
		warning("UdpAliveTimeout [%s] invalid: %v", udpAliveTimeout, err)
		return kDefaultUdpAliveTimeout
	}
	return time.Duration(timeoutSeconds) * time.Second
}

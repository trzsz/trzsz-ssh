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
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// fakeListener is a remote listener whose accepted connections are injected by the test.
type fakeListener struct {
	conns     chan net.Conn
	done      chan struct{}
	closeOnce sync.Once
	addr      net.Addr
}

func (l *fakeListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *fakeListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return nil
}

func (l *fakeListener) Addr() net.Addr {
	if l.addr != nil {
		return l.addr
	}
	return &net.TCPAddr{}
}

func (l *fakeListener) isClosed() bool {
	select {
	case <-l.done:
		return true
	default:
		return false
	}
}

// fakeSshClient is an in-memory SshClient backend for the mux proxy tests.
type fakeSshClient struct {
	mu        sync.Mutex
	sessions  []*fakeSshSession
	listeners map[string]*fakeListener
	dialFn    func(network, addr string) (net.Conn, error)
	closed    bool
}

func newFakeSshClient() *fakeSshClient {
	return &fakeSshClient{listeners: make(map[string]*fakeListener)}
}

func (c *fakeSshClient) Wait() error { return nil }

func (c *fakeSshClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *fakeSshClient) NewSession() (SshSession, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := newFakeSshSession()
	c.sessions = append(c.sessions, s)
	return s, nil
}

func (c *fakeSshClient) session(idx int) *fakeSshSession {
	c.mu.Lock()
	defer c.mu.Unlock()
	if idx < len(c.sessions) {
		return c.sessions[idx]
	}
	return nil
}

func (c *fakeSshClient) DialTimeout(network, addr string, timeout time.Duration) (net.Conn, error) {
	if c.dialFn == nil {
		return nil, fmt.Errorf("dial %s %s refused", network, addr)
	}
	return c.dialFn(network, addr)
}

var fakeListenPort atomic.Int32

func (c *fakeSshClient) Listen(network, addr string) (net.Listener, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if portStr == "0" {
		portStr = strconv.Itoa(int(fakeListenPort.Add(1)) + 40000)
	}
	actualAddr := net.JoinHostPort(host, portStr)
	port, _ := strconv.Atoi(portStr)
	ip := net.ParseIP(host)
	if ip == nil {
		ip = net.IPv4zero
	}
	l := &fakeListener{
		conns: make(chan net.Conn, 4),
		done:  make(chan struct{}),
		addr:  &net.TCPAddr{IP: ip, Port: port},
	}
	c.listeners[network+"|"+actualAddr] = l
	return l, nil
}

func (c *fakeSshClient) listener(key string) *fakeListener {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.listeners[key]
}

func (c *fakeSshClient) ListenUDP(network, addr string) (PacketListener, error) {
	return nil, fmt.Errorf("ListenUDP not supported")
}

func (c *fakeSshClient) HandleChannelOpen(channelType string) <-chan ssh.NewChannel { return nil }

func (c *fakeSshClient) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	return false, nil, fmt.Errorf("global request not supported")
}

func (c *fakeSshClient) DialUDP(network, addr string, timeout time.Duration) (PacketConn, error) {
	return nil, fmt.Errorf("DialUDP not supported")
}

// fakeSshSession mimics the ordering rules of tsshd.SshUdpSession.
type fakeSshSession struct {
	mu         sync.Mutex
	term       string
	rows, cols int
	modes      ssh.TerminalModes
	envs       map[string]string
	shell      bool
	cmd        string
	subsystem  string
	started    bool
	closed     bool
	exitCode   int
	requests   []string
	winChanges [][2]int
	startedCh  chan struct{}
	exitCh     chan struct{}
	closedCh   chan struct{}
	stdinR     *io.PipeReader
	stdinW     *io.PipeWriter
	stdoutR    *io.PipeReader
	stdoutW    *io.PipeWriter
	stderrR    *io.PipeReader
	stderrW    *io.PipeWriter
}

func newFakeSshSession() *fakeSshSession {
	s := &fakeSshSession{
		envs:      make(map[string]string),
		startedCh: make(chan struct{}),
		exitCh:    make(chan struct{}),
		closedCh:  make(chan struct{}),
	}
	s.stdinR, s.stdinW = io.Pipe()
	s.stdoutR, s.stdoutW = io.Pipe()
	s.stderrR, s.stderrW = io.Pipe()
	return s
}

func (s *fakeSshSession) start(fn func()) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return errors.New("session already started")
	}
	fn()
	s.started = true
	close(s.startedCh)
	return nil
}

func (s *fakeSshSession) waitStarted(t *testing.T) {
	select {
	case <-s.startedCh:
	case <-time.After(5 * time.Second):
		t.Fatal("session not started in time")
	}
}

// finish ends the remote command: closes the output pipes and unblocks Wait.
func (s *fakeSshSession) finish(code int) {
	s.mu.Lock()
	s.exitCode = code
	s.mu.Unlock()
	_ = s.stdoutW.Close()
	_ = s.stderrW.Close()
	close(s.exitCh)
}

func (s *fakeSshSession) Wait() error {
	<-s.exitCh
	return nil
}

func (s *fakeSshSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	close(s.closedCh)
	_ = s.stdinR.Close()
	_ = s.stdoutW.Close()
	_ = s.stderrW.Close()
	return nil
}

func (s *fakeSshSession) Shell() error { return s.start(func() { s.shell = true }) }

func (s *fakeSshSession) Run(cmd string) error {
	if err := s.Start(cmd); err != nil {
		return err
	}
	return s.Wait()
}

func (s *fakeSshSession) Start(cmd string) error { return s.start(func() { s.cmd = cmd }) }

func (s *fakeSshSession) RequestSubsystem(name string) error {
	return s.start(func() { s.subsystem = name })
}

func (s *fakeSshSession) WindowChange(height, width int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.winChanges = append(s.winChanges, [2]int{height, width})
	return nil
}

func (s *fakeSshSession) Setenv(name, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return errors.New("session already started")
	}
	s.envs[name] = value
	return nil
}

func (s *fakeSshSession) StdinPipe() (io.WriteCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return nil, errors.New("session already started")
	}
	return s.stdinW, nil
}

func (s *fakeSshSession) StdoutPipe() (io.Reader, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return nil, errors.New("session already started")
	}
	return s.stdoutR, nil
}

func (s *fakeSshSession) StderrPipe() (io.Reader, error) { return s.stderrR, nil }

func (s *fakeSshSession) Output(cmd string) ([]byte, error) { return nil, errors.New("not supported") }

func (s *fakeSshSession) CombinedOutput(cmd string) ([]byte, error) {
	return nil, errors.New("not supported")
}

func (s *fakeSshSession) RequestPty(term string, height, width int, modes ssh.TerminalModes) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return errors.New("session already started")
	}
	s.term, s.rows, s.cols, s.modes = term, height, width, modes
	return nil
}

func (s *fakeSshSession) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, name)
	switch name {
	case "x11-req", "auth-agent-req@openssh.com":
		return true, nil
	default:
		return false, fmt.Errorf("unsupported request: %s", name)
	}
}

func (s *fakeSshSession) RedrawScreen(discardPreviousOutput bool) error { return nil }

func (s *fakeSshSession) GetTerminalWidth() int { return s.cols }

func (s *fakeSshSession) GetExitCode() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.exitCode
}

// newMuxTestClient connects an x/crypto mux proxy client to a muxProxyConn over loopback tcp.
func newMuxTestClient(t *testing.T, backend SshClient) (*ssh.Client, *muxProxyConn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()

	pcCh := make(chan *muxProxyConn, 1)
	go func() {
		serverSide, err := listener.Accept()
		if err != nil {
			pcCh <- nil
			return
		}
		if err := muxAcceptProxyHandshake(serverSide); err != nil {
			_ = serverSide.Close()
			pcCh <- nil
			return
		}
		pc := newMuxProxyConn(serverSide, backend, nil)
		pcCh <- pc
		pc.serve()
	}()

	clientSide, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	conn, chans, reqs, err := ssh.NewControlClientConn(clientSide)
	require.NoError(t, err)
	client := ssh.NewClient(conn, chans, reqs)
	pc := <-pcCh
	require.NotNil(t, pc)
	t.Cleanup(func() {
		_ = client.Close()
		pc.close()
	})
	return client, pc
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func TestMuxProxyExecExitStatus(t *testing.T) {
	backend := newFakeSshClient()
	client, _ := newMuxTestClient(t, backend)

	sess, err := client.NewSession()
	require.NoError(t, err)
	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr
	require.NoError(t, sess.Start("ls -l"))

	fs := backend.session(0)
	require.NotNil(t, fs)
	fs.waitStarted(t)
	assert.Equal(t, "ls -l", fs.cmd)

	_, err = fs.stdoutW.Write([]byte("hello\n"))
	require.NoError(t, err)
	_, err = fs.stderrW.Write([]byte("warn\n"))
	require.NoError(t, err)
	fs.finish(3)

	err = sess.Wait()
	var exitErr *ssh.ExitError
	require.ErrorAs(t, err, &exitErr)
	assert.Equal(t, 3, exitErr.ExitStatus())
	assert.Equal(t, "hello\n", stdout.String())
	assert.Equal(t, "warn\n", stderr.String())
	_ = sess.Close()

	waitFor(t, "backend session closed", func() bool {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		return fs.closed
	})
}

func TestMuxProxyShellPtyEnvStdin(t *testing.T) {
	backend := newFakeSshClient()
	client, _ := newMuxTestClient(t, backend)

	sess, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, sess.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 38400}))
	require.NoError(t, sess.Setenv("FOO", "bar"))
	stdin, err := sess.StdinPipe()
	require.NoError(t, err)
	var stdout bytes.Buffer
	sess.Stdout = &stdout
	require.NoError(t, sess.Shell())

	fs := backend.session(0)
	require.NotNil(t, fs)
	fs.waitStarted(t)
	assert.True(t, fs.shell)
	assert.Equal(t, "xterm-256color", fs.term)
	assert.Equal(t, 24, fs.rows)
	assert.Equal(t, 80, fs.cols)
	assert.Equal(t, uint32(1), fs.modes[ssh.ECHO])
	assert.Equal(t, uint32(38400), fs.modes[ssh.TTY_OP_ISPEED])
	assert.Equal(t, "bar", fs.envs["FOO"])

	// pty-req after start must fail
	assert.Error(t, sess.RequestPty("vt100", 1, 1, nil))

	_, err = stdin.Write([]byte("abc"))
	require.NoError(t, err)
	buf := make([]byte, 3)
	_, err = io.ReadFull(fs.stdinR, buf)
	require.NoError(t, err)
	assert.Equal(t, "abc", string(buf))

	require.NoError(t, sess.WindowChange(30, 100))
	waitFor(t, "window change", func() bool {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		return len(fs.winChanges) == 1 && fs.winChanges[0] == [2]int{30, 100}
	})

	// x11 and agent requests are refused by the master
	ok, err := sess.SendRequest("x11-req", true, nil)
	require.NoError(t, err)
	assert.False(t, ok)

	// stdin EOF propagates to the backend
	require.NoError(t, stdin.Close())
	_, err = fs.stdinR.Read(buf)
	assert.ErrorIs(t, err, io.EOF)

	_, err = fs.stdoutW.Write([]byte("$ "))
	require.NoError(t, err)
	fs.finish(0)
	require.NoError(t, sess.Wait())
	assert.Equal(t, "$ ", stdout.String())
}

func TestMuxProxyDirectTcpip(t *testing.T) {
	backend := newFakeSshClient()
	var dialedNetwork, dialedAddr string
	backend.dialFn = func(network, addr string) (net.Conn, error) {
		dialedNetwork, dialedAddr = network, addr
		local, remote := net.Pipe()
		go func() {
			_, _ = io.Copy(remote, remote) // echo
			_ = remote.Close()
		}()
		return local, nil
	}
	client, _ := newMuxTestClient(t, backend)

	conn, err := client.Dial("tcp", "10.0.0.1:8080")
	require.NoError(t, err)
	assert.Equal(t, "tcp", dialedNetwork)
	assert.Equal(t, "10.0.0.1:8080", dialedAddr)

	payload := make([]byte, 1024*1024) // exercise window handling and packet chunking
	_, err = rand.Read(payload)
	require.NoError(t, err)
	go func() {
		_, _ = conn.Write(payload)
	}()
	got := make([]byte, len(payload))
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(payload, got))
	require.NoError(t, conn.Close())
}

func TestMuxProxyDirectTcpipDialFailure(t *testing.T) {
	backend := newFakeSshClient()
	client, _ := newMuxTestClient(t, backend)
	_, err := client.Dial("tcp", "10.0.0.1:8080")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refused")
}

func TestMuxProxyDirectStreamLocal(t *testing.T) {
	backend := newFakeSshClient()
	var dialedNetwork, dialedAddr string
	backend.dialFn = func(network, addr string) (net.Conn, error) {
		dialedNetwork, dialedAddr = network, addr
		local, remote := net.Pipe()
		go func() {
			_, _ = remote.Write([]byte("unix ok"))
			_ = remote.Close()
		}()
		return local, nil
	}
	client, _ := newMuxTestClient(t, backend)

	conn, err := client.Dial("unix", "/tmp/some.sock")
	require.NoError(t, err)
	assert.Equal(t, "unix", dialedNetwork)
	assert.Equal(t, "/tmp/some.sock", dialedAddr)
	data, err := io.ReadAll(conn)
	require.NoError(t, err)
	assert.Equal(t, "unix ok", string(data))
}

func TestMuxProxyRemoteForward(t *testing.T) {
	backend := newFakeSshClient()
	client, _ := newMuxTestClient(t, backend)

	listener, err := client.Listen("tcp", "127.0.0.1:9000")
	require.NoError(t, err)
	fl := backend.listener("tcp|127.0.0.1:9000")
	require.NotNil(t, fl)

	remoteSide, injected := net.Pipe()
	fl.conns <- injected

	conn, err := listener.Accept()
	require.NoError(t, err)
	go func() {
		_, _ = remoteSide.Write([]byte("ping"))
	}()
	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	assert.Equal(t, "ping", string(buf))

	go func() {
		_, _ = conn.Write([]byte("pong"))
	}()
	_, err = io.ReadFull(remoteSide, buf)
	require.NoError(t, err)
	assert.Equal(t, "pong", string(buf))

	require.NoError(t, conn.Close())
	require.NoError(t, listener.Close())
	waitFor(t, "remote listener closed", fl.isClosed)
}

func TestMuxProxyRemoteForwardPortZero(t *testing.T) {
	backend := newFakeSshClient()
	client, _ := newMuxTestClient(t, backend)
	listener, err := client.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	require.NotNil(t, listener)

	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	require.True(t, ok)
	require.Greater(t, tcpAddr.Port, 0)

	actualAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(tcpAddr.Port))
	fl := backend.listener("tcp|" + actualAddr)
	require.NotNil(t, fl)

	require.NoError(t, listener.Close())
	waitFor(t, "remote listener closed", fl.isClosed)
}

func TestMuxProxyGlobalRequests(t *testing.T) {
	backend := newFakeSshClient()
	client, _ := newMuxTestClient(t, backend)

	ok, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
	require.NoError(t, err)
	assert.True(t, ok)

	ok, _, err = client.SendRequest("no-such-request@example.com", true, nil)
	require.NoError(t, err)
	assert.False(t, ok)

	assert.True(t, isUdpMuxMaster(&sshClientWrapper{client: client}))
}

func TestMuxProxyClientDisconnectCleansUp(t *testing.T) {
	backend := newFakeSshClient()
	client, pc := newMuxTestClient(t, backend)

	sess, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, sess.Shell())
	fs := backend.session(0)
	require.NotNil(t, fs)
	fs.waitStarted(t)

	_, err = client.Listen("tcp", "0.0.0.0:9100")
	require.NoError(t, err)
	fl := backend.listener("tcp|0.0.0.0:9100")
	require.NotNil(t, fl)

	require.NoError(t, client.Close())
	waitFor(t, "proxy conn closed", func() bool { return pc.closed.Load() })
	waitFor(t, "backend session closed", func() bool {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		return fs.closed
	})
	waitFor(t, "remote listener closed", fl.isClosed)
	assert.Empty(t, pc.chans)
}

func TestMuxProxyConcurrentSessions(t *testing.T) {
	backend := newFakeSshClient()
	client, _ := newMuxTestClient(t, backend)

	const count = 10
	var wg sync.WaitGroup
	results := make([]string, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sess, err := client.NewSession()
			if !assert.NoError(t, err) {
				return
			}
			defer func() { _ = sess.Close() }()
			var out bytes.Buffer
			sess.Stdout = &out
			if !assert.NoError(t, sess.Start(fmt.Sprintf("cmd-%d", i))) {
				return
			}
			assert.NoError(t, sess.Wait())
			results[i] = out.String()
		}(i)
	}

	// answer each backend session with its own command
	waitFor(t, "all sessions", func() bool {
		backend.mu.Lock()
		defer backend.mu.Unlock()
		return len(backend.sessions) == count
	})
	for i := 0; i < count; i++ {
		fs := backend.session(i)
		fs.waitStarted(t)
		_, err := fs.stdoutW.Write([]byte("out of " + fs.cmd))
		require.NoError(t, err)
		fs.finish(0)
	}
	wg.Wait()

	seen := make(map[string]bool)
	for _, r := range results {
		seen[r] = true
	}
	for i := 0; i < count; i++ {
		assert.True(t, seen[fmt.Sprintf("out of cmd-%d", i)], "missing output of session %d", i)
	}
}

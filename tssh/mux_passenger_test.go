//go:build !windows

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
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/term"
)

// passengerFiles holds the client ends of the pipes a passenger hands to the master.
type passengerFiles struct {
	stdinW  *os.File // test writes the passenger's input here
	stdoutR *os.File // test reads the passenger's output here
	stderrR *os.File
	stdin   *os.File // passed to the master
	stdout  *os.File
	stderr  *os.File
}

func newPassengerFiles(t *testing.T) *passengerFiles {
	t.Helper()
	var f passengerFiles
	var err error
	f.stdin, f.stdinW, err = os.Pipe()
	require.NoError(t, err)
	f.stdoutR, f.stdout, err = os.Pipe()
	require.NoError(t, err)
	f.stderrR, f.stderr, err = os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() {
		for _, file := range []*os.File{f.stdinW, f.stdoutR, f.stderrR, f.stdin, f.stdout, f.stderr} {
			_ = file.Close()
		}
	})
	return &f
}

func readAllWithTimeout(t *testing.T, r io.Reader, want int) string {
	t.Helper()
	buf := make([]byte, want)
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(r, buf)
		done <- err
	}()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout reading passenger output")
	}
	return string(buf)
}

func TestMuxFdRoundTrip(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	require.NoError(t, err)
	fileA := os.NewFile(uintptr(fds[0]), "a")
	fileB := os.NewFile(uintptr(fds[1]), "b")
	connA, err := net.FileConn(fileA)
	require.NoError(t, err)
	connB, err := net.FileConn(fileB)
	require.NoError(t, err)
	_ = fileA.Close()
	_ = fileB.Close()
	defer func() { _ = connA.Close(); _ = connB.Close() }()

	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer func() { _ = r.Close() }()

	require.NoError(t, muxSendFd(connA.(*net.UnixConn), int(w.Fd())))
	_ = w.Close()
	received, err := muxRecvFd(connB.(*net.UnixConn), "received")
	require.NoError(t, err)
	_, err = received.Write([]byte("via fd"))
	require.NoError(t, err)
	_ = received.Close()
	data, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, "via fd", string(data))
}

func TestMuxPassengerExecExitStatus(t *testing.T) {
	backend := newFakeSshClient()
	m, socket := newTestMuxMaster(t, backend, nil)
	m.param.args.Option = sshOption{options: map[string][]string{"sendenv": {"FOO_*"}}}

	client, err := dialMuxMaster(socket, time.Second)
	require.NoError(t, err)
	defer client.close()
	assert.True(t, client.tsshMaster)
	pid, err := client.aliveCheck()
	require.NoError(t, err)
	assert.Equal(t, uint32(os.Getpid()), pid)

	files := newPassengerFiles(t)
	req := &muxNewSessionRequest{command: "ls -l", escapeChar: kMuxEscapeCharNone, term: "xterm",
		envs: []string{"FOO_BAR=1", "SECRET=2"}}
	sessionID, err := client.newSession(req, files.stdin, files.stdout, files.stderr)
	require.NoError(t, err)
	waitFor(t, "one passenger", func() bool { return m.clientCount() == 1 })

	fs := backend.session(0)
	require.NotNil(t, fs)
	fs.waitStarted(t)
	assert.Equal(t, "ls -l", fs.cmd)
	assert.Equal(t, "1", fs.envs["FOO_BAR"])
	_, secretSent := fs.envs["SECRET"]
	assert.False(t, secretSent, "env not matching SendEnv must not be sent")
	assert.Equal(t, "", fs.term, "no pty was requested")

	// stdin reaches the remote command
	_, err = files.stdinW.Write([]byte("input"))
	require.NoError(t, err)
	buf := make([]byte, 5)
	_, err = io.ReadFull(fs.stdinR, buf)
	require.NoError(t, err)
	assert.Equal(t, "input", string(buf))

	_, err = fs.stdoutW.Write([]byte("hello\n"))
	require.NoError(t, err)
	_, err = fs.stderrW.Write([]byte("warn\n"))
	require.NoError(t, err)
	assert.Equal(t, "hello\n", readAllWithTimeout(t, files.stdoutR, 6))
	assert.Equal(t, "warn\n", readAllWithTimeout(t, files.stderrR, 5))

	fs.finish(3)
	assert.Equal(t, 3, client.waitExit(sessionID, nil))
	waitFor(t, "passenger gone", func() bool { return m.clientCount() == 0 })
	waitFor(t, "backend session closed", func() bool {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		return fs.closed
	})
}

func TestMuxPassengerPtyAndWindowChange(t *testing.T) {
	backend := newFakeSshClient()
	m, socket := newTestMuxMaster(t, backend, nil)

	ptmx, tty, err := pty.Open()
	require.NoError(t, err)
	defer func() { _ = ptmx.Close(); _ = tty.Close() }()
	require.NoError(t, pty.Setsize(ptmx, &pty.Winsize{Rows: 24, Cols: 80}))

	client, err := dialMuxMaster(socket, time.Second)
	require.NoError(t, err)
	defer client.close()

	req := &muxNewSessionRequest{wantTTY: true, term: "xterm-256color", escapeChar: kMuxEscapeCharNone}
	sessionID, err := client.newSession(req, tty, tty, tty)
	require.NoError(t, err)

	fs := backend.session(0)
	require.NotNil(t, fs)
	fs.waitStarted(t)
	assert.True(t, fs.shell)
	assert.Equal(t, "xterm-256color", fs.term)
	assert.Equal(t, 24, fs.rows)
	assert.Equal(t, 80, fs.cols)

	// the passenger client relays SIGWINCH to the master process
	require.NoError(t, pty.Setsize(ptmx, &pty.Winsize{Rows: 40, Cols: 120}))
	require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGWINCH))
	waitFor(t, "window change", func() bool {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		return len(fs.winChanges) > 0 && fs.winChanges[len(fs.winChanges)-1] == [2]int{40, 120}
	})

	// output written by the remote shows up on the terminal
	_, err = fs.stdoutW.Write([]byte("$ "))
	require.NoError(t, err)
	assert.Equal(t, "$ ", readAllWithTimeout(t, ptmx, 2))

	fs.finish(0)
	assert.Equal(t, 0, client.waitExit(sessionID, nil))
	waitFor(t, "passenger gone", func() bool { return m.clientCount() == 0 })
}

func TestMuxPassengerTtyAllocFail(t *testing.T) {
	backend := newFakeSshClient()
	_, socket := newTestMuxMaster(t, backend, nil)
	client, err := dialMuxMaster(socket, time.Second)
	require.NoError(t, err)
	defer client.close()

	// pipes are not terminals, so the pty request fails and the session runs without one
	files := newPassengerFiles(t)
	req := &muxNewSessionRequest{wantTTY: true, command: "true", escapeChar: kMuxEscapeCharNone}
	sessionID, err := client.newSession(req, files.stdin, files.stdout, files.stderr)
	require.NoError(t, err)
	fs := backend.session(0)
	require.NotNil(t, fs)
	fs.waitStarted(t)
	assert.Equal(t, "", fs.term)
	fs.finish(0)
	ttyFail := false
	assert.Equal(t, 0, client.waitExit(sessionID, func() { ttyFail = true }))
	assert.True(t, ttyFail)
}

func TestMuxPassengerDisconnectClosesSession(t *testing.T) {
	backend := newFakeSshClient()
	m, socket := newTestMuxMaster(t, backend, nil)
	client, err := dialMuxMaster(socket, time.Second)
	require.NoError(t, err)

	files := newPassengerFiles(t)
	_, err = client.newSession(&muxNewSessionRequest{escapeChar: kMuxEscapeCharNone}, files.stdin, files.stdout, files.stderr)
	require.NoError(t, err)
	fs := backend.session(0)
	require.NotNil(t, fs)
	fs.waitStarted(t)

	client.close()
	waitFor(t, "backend session closed", func() bool {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		return fs.closed
	})
	waitFor(t, "passenger gone", func() bool { return m.clientCount() == 0 })
}

func TestMuxPassengerStdioForward(t *testing.T) {
	backend := newFakeSshClient()
	var dialed string
	backend.dialFn = func(network, addr string) (net.Conn, error) {
		dialed = addr
		local, remote := net.Pipe()
		go func() {
			_, _ = io.Copy(remote, remote)
			_ = remote.Close()
		}()
		return local, nil
	}
	m, socket := newTestMuxMaster(t, backend, nil)
	client, err := dialMuxMaster(socket, time.Second)
	require.NoError(t, err)
	defer client.close()

	files := newPassengerFiles(t)
	_, err = client.stdioForward("10.0.0.1", 22, files.stdin, files.stdout)
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.1:22", dialed)
	// a running stdio forward is a connected client
	waitFor(t, "one stdio forward client", func() bool { return m.clientCount() == 1 })
	_, err = files.stdinW.Write([]byte("SSH-2.0-test"))
	require.NoError(t, err)
	assert.Equal(t, "SSH-2.0-test", readAllWithTimeout(t, files.stdoutR, 12))

	client.close()
	waitFor(t, "stdio forward client gone", func() bool { return m.clientCount() == 0 })
}

func TestMuxMasterCloseEndsStdioForward(t *testing.T) {
	backend := newFakeSshClient()
	backend.dialFn = func(network, addr string) (net.Conn, error) {
		local, remote := net.Pipe()
		go func() {
			_, _ = io.Copy(io.Discard, remote)
			_ = remote.Close()
		}()
		return local, nil
	}
	m, socket := newTestMuxMaster(t, backend, nil)
	client, err := dialMuxMaster(socket, time.Second)
	require.NoError(t, err)
	defer client.close()

	files := newPassengerFiles(t)
	_, err = client.stdioForward("10.0.0.1", 22, files.stdin, files.stdout)
	require.NoError(t, err)
	waitFor(t, "one stdio forward client", func() bool { return m.clientCount() == 1 })

	// closing the master tears the forwarding down: the client sees EOF
	m.close()
	assert.Equal(t, 0, m.clientCount())
	buf := make([]byte, 1)
	_ = client.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = client.conn.Read(buf)
	assert.ErrorIs(t, err, io.EOF)
}

func freeLocalPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return port
}

func TestMuxPassengerOpenAndCloseForward(t *testing.T) {
	backend := newFakeSshClient()
	backend.dialFn = func(network, addr string) (net.Conn, error) {
		local, remote := net.Pipe()
		go func() {
			_, _ = remote.Write([]byte("fwd:" + addr))
			_ = remote.Close()
		}()
		return local, nil
	}
	_, socket := newTestMuxMaster(t, backend, nil)
	client, err := dialMuxMaster(socket, time.Second)
	require.NoError(t, err)
	defer client.close()

	port := freeLocalPort(t)
	host := "127.0.0.1"
	req := &muxForwardRequest{ftype: kMuxFwdLocal, listenHost: host, listenPort: uint32(port), connectHost: "db", connectPort: 5432}
	_, err = client.openForward(req)
	require.NoError(t, err)
	_, err = client.openForward(req)
	assert.Error(t, err, "duplicate forwarding must be refused")

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), time.Second)
	require.NoError(t, err)
	data, err := io.ReadAll(conn)
	require.NoError(t, err)
	assert.Equal(t, "fwd:db:5432", string(data))
	_ = conn.Close()

	require.NoError(t, client.closeForward(req))
	assert.Error(t, client.closeForward(req))
	_, err = net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 500*time.Millisecond)
	assert.Error(t, err, "listener must be closed after cancel")

	// remote forwardings register a listener on the backend
	remote := &muxForwardRequest{ftype: kMuxFwdRemote, listenHost: "0.0.0.0", listenPort: 9000, connectHost: "localhost", connectPort: 80}
	_, err = client.openForward(remote)
	require.NoError(t, err)
	assert.NotNil(t, backend.listener("tcp|0.0.0.0:9000"))
	_, err = client.openForward(&muxForwardRequest{ftype: kMuxFwdRemote, listenHost: "0.0.0.0", listenPort: 0, connectHost: "localhost", connectPort: 80})
	assert.Error(t, err, "port 0 is not supported")
}

func TestMuxPassengerEligible(t *testing.T) {
	oriUserConfig := userConfig
	userConfig = &tsshConfig{}
	defer func() { userConfig = oriUserConfig }()

	plain := func() *sshArgs {
		return &sshArgs{Destination: "e2e-target", Option: sshOption{options: map[string][]string{
			"forwardx11": {"no"}, "forwardagent": {"no"}}}}
	}
	assert.True(t, muxPassengerEligible(plain()))

	x11 := plain()
	x11.X11Forward = true
	assert.False(t, muxPassengerEligible(x11))

	agent := plain()
	agent.ForwardAgent = true
	assert.False(t, muxPassengerEligible(agent))
	agent.NoForwardAgent = true
	assert.True(t, muxPassengerEligible(agent))

	upload := plain()
	upload.UploadFile.values = []string{"file"}
	assert.False(t, muxPassengerEligible(upload))

	udpForward := plain()
	udpForward.LocalForward.cfgs = []*forwardCfg{{udp: true}}
	assert.False(t, muxPassengerEligible(udpForward))
}

// TestRunAsMuxPassenger runs a login as passenger of a tssh master on this process's stdio.
func TestRunAsMuxPassenger(t *testing.T) {
	backend := newFakeSshClient()
	m, socket := newTestMuxMaster(t, backend, nil)

	// replace the process stdio with pipes for the duration of the test
	oriStdin, oriStdout, oriStderr := os.Stdin, os.Stdout, os.Stderr
	files := newPassengerFiles(t)
	os.Stdin, os.Stdout, os.Stderr = files.stdin, files.stdout, files.stderr
	defer func() { os.Stdin, os.Stdout, os.Stderr = oriStdin, oriStdout, oriStderr }()

	args := &sshArgs{Destination: "e2e-target", Command: "uname", ControlPath: socket,
		Option: sshOption{options: map[string][]string{"controlmaster": {"no"}, "forwardx11": {"no"}, "forwardagent": {"no"}}}}
	param, err := getSshParam(args, false)
	require.NoError(t, err)

	type result struct {
		code    int
		handled bool
	}
	done := make(chan result, 1)
	go func() {
		code, handled := runAsMuxPassenger(param)
		done <- result{code, handled}
	}()

	waitFor(t, "one passenger", func() bool { return m.clientCount() == 1 })
	fs := backend.session(0)
	require.NotNil(t, fs)
	fs.waitStarted(t)
	assert.Equal(t, "uname", fs.cmd)
	_, err = fs.stdoutW.Write([]byte("Darwin\n"))
	require.NoError(t, err)
	assert.Equal(t, "Darwin\n", readAllWithTimeout(t, files.stdoutR, 7))
	fs.finish(5)

	select {
	case r := <-done:
		assert.True(t, r.handled)
		assert.Equal(t, 5, r.code)
	case <-time.After(5 * time.Second):
		t.Fatal("passenger did not finish")
	}

	// a login that needs proxy mode is not served as passenger
	args.X11Forward = true
	_, handled := runAsMuxPassenger(param)
	assert.False(t, handled)
}

func TestMuxEscapeReader(t *testing.T) {
	tests := []struct {
		name       string
		reads      []string
		escapeChar byte
		output     string
		terminated bool
		help       bool
	}{
		{name: "terminate after newline", reads: []string{"ls\r~.rest"}, escapeChar: '~', output: "ls\r", terminated: true},
		{name: "terminate at start", reads: []string{"~."}, escapeChar: '~', terminated: true},
		{name: "split across reads", reads: []string{"a\r~", "."}, escapeChar: '~', output: "a\r", terminated: true},
		{name: "double escape sends one", reads: []string{"~~x"}, escapeChar: '~', output: "~x"},
		{name: "not after newline", reads: []string{"a~.b"}, escapeChar: '~', output: "a~.b"},
		{name: "unknown sequence passes", reads: []string{"\n~x"}, escapeChar: '~', output: "\n~x"},
		{name: "help", reads: []string{"\r~?ok"}, escapeChar: '~', output: "\rok", help: true},
		{name: "control char escape", reads: []string{"\r\x02."}, escapeChar: 0x02, output: "\r", terminated: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader, writer := io.Pipe()
			go func() {
				for _, s := range tt.reads {
					_, _ = writer.Write([]byte(s))
				}
				_ = writer.Close()
			}()
			var stderr strings.Builder
			terminated := false
			r := &muxEscapeReader{reader: reader, escapeChar: tt.escapeChar, stderr: &stderr,
				terminate: func() { terminated = true }, afterNewline: true}
			out, err := io.ReadAll(r)
			require.NoError(t, err)
			assert.Equal(t, tt.output, string(out))
			assert.Equal(t, tt.terminated, terminated)
			assert.Equal(t, tt.help, strings.Contains(stderr.String(), "Supported escape sequences"))
		})
	}
}

func TestMuxPassengerEscapeTerminatesSession(t *testing.T) {
	backend := newFakeSshClient()
	m, socket := newTestMuxMaster(t, backend, nil)

	ptmx, tty, err := pty.Open()
	require.NoError(t, err)
	defer func() { _ = ptmx.Close(); _ = tty.Close() }()
	require.NoError(t, pty.Setsize(ptmx, &pty.Winsize{Rows: 24, Cols: 80}))
	// the passenger client puts its terminal in raw mode
	_, err = term.MakeRaw(int(tty.Fd()))
	require.NoError(t, err)

	client, err := dialMuxMaster(socket, time.Second)
	require.NoError(t, err)
	defer client.close()

	req := &muxNewSessionRequest{wantTTY: true, term: "xterm", escapeChar: '~'}
	sessionID, err := client.newSession(req, tty, tty, tty)
	require.NoError(t, err)
	fs := backend.session(0)
	require.NotNil(t, fs)
	fs.waitStarted(t)
	go func() { _, _ = io.Copy(io.Discard, fs.stdinR) }()

	_, err = ptmx.Write([]byte("\r~."))
	require.NoError(t, err)
	// no exit message after ~. so the client exits with 255, like OpenSSH
	assert.Equal(t, 255, client.waitExit(sessionID, nil))
	waitFor(t, "passenger gone", func() bool { return m.clientCount() == 0 })
	waitFor(t, "backend session closed", func() bool {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		return fs.closed
	})
}

func TestMuxPassengerAgentAndX11Requests(t *testing.T) {
	backend := newFakeSshClient()
	m, socket := newTestMuxMaster(t, backend, nil)

	// a listening agent socket of the master (short path, see newTestMuxMaster)
	dir, err := os.MkdirTemp("", "tsshagent")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(dir) }()
	agentSocket := filepath.Join(dir, "agent")
	agentListener, err := net.Listen("unix", agentSocket)
	require.NoError(t, err)
	defer func() { _ = agentListener.Close() }()
	t.Setenv("SSH_AUTH_SOCK", agentSocket)
	t.Setenv("DISPLAY", "")

	client, err := dialMuxMaster(socket, time.Second)
	require.NoError(t, err)
	defer client.close()

	files := newPassengerFiles(t)
	req := &muxNewSessionRequest{command: "true", wantAgent: true, wantX11: true, escapeChar: kMuxEscapeCharNone}
	sessionID, err := client.newSession(req, files.stdin, files.stdout, files.stderr)
	require.NoError(t, err)
	fs := backend.session(0)
	require.NotNil(t, fs)
	fs.waitStarted(t)

	fs.mu.Lock()
	requests := append([]string(nil), fs.requests...)
	fs.mu.Unlock()
	// the agent of the master is forwarded; without DISPLAY there is no X11 forwarding, the session still runs
	assert.Contains(t, requests, kAgentRequestName)
	assert.NotContains(t, requests, kX11RequestName)
	assert.True(t, m.agentForwarded)
	assert.NotNil(t, backend.channel(kAgentChannelType), "agent channels must be handled on the master connection")
	assert.Nil(t, backend.channel(kX11ChannelType))

	fs.finish(0)
	assert.Equal(t, 0, client.waitExit(sessionID, nil))
}

func TestMuxPassengerRouting(t *testing.T) {
	oriUserConfig := userConfig
	userConfig = &tsshConfig{}
	defer func() { userConfig = oriUserConfig }()

	newParam := func(udpMode udpModeType, options map[string][]string) *sshParam {
		return &sshParam{args: &sshArgs{Destination: "route-host", Option: sshOption{options: options}}, udpMode: udpMode}
	}

	// an OpenSSH master can run the session only if tssh does not need the session output
	assert.False(t, muxOpenSSHPassengerEligible(newParam(kUdpModeNo, nil)), "trzsz is enabled by default")
	assert.True(t, muxOpenSSHPassengerEligible(newParam(kUdpModeNo, map[string][]string{"enabletrzsz": {"no"}})))
	assert.False(t, muxOpenSSHPassengerEligible(newParam(kUdpModeYes, map[string][]string{"enabletrzsz": {"no"}})),
		"udp mode needs proxy mode to start tsshd")

	// auto interaction reads the session output, so it needs proxy mode
	assert.True(t, muxPassengerEligible(newParam(kUdpModeNo, nil).args))
	assert.False(t, muxPassengerEligible(newParam(kUdpModeNo, map[string][]string{"expectcount": {"1"}}).args))

	assert.Equal(t, uint32('~'), muxPassengerEscapeChar(newParam(kUdpModeNo, nil).args))
	assert.Equal(t, kMuxEscapeCharNone, muxPassengerEscapeChar(newParam(kUdpModeNo, map[string][]string{"escapechar": {"none"}}).args))
}

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
	"bytes"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// The tests in this file drive a tssh control master with the real OpenSSH client,
// which uses the mux passenger mode. They are skipped when no ssh binary is installed.

func opensshPath(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("openssh client not installed")
	}
	return path
}

// runOpenSSH runs `ssh -S socket <args...>` and returns stdout, stderr and the exit code.
func runOpenSSH(t *testing.T, sshPath, socket string, stdin string, args ...string) (string, string, int) {
	t.Helper()
	cmdArgs := append([]string{"-F", "/dev/null", "-o", "BatchMode=yes", "-o", "ControlMaster=no", "-S", socket}, args...)
	cmd := exec.Command(sshPath, cmdArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run ssh failed: %v", err)
		}
		code = exitErr.ExitCode()
	}
	return stdout.String(), stderr.String(), code
}

// startTcpMuxMaster logs in to the loopback ssh server and serves a control socket for it,
// terminate replaces the process exit of a `-O exit` request.
func startTcpMuxMaster(t *testing.T, terminate func()) (*testSshServer, *muxMaster, string) {
	t.Helper()
	server := startTestSshServer(t)
	tcpConn, err := net.DialTimeout("tcp", server.listener.Addr().String(), 5*time.Second)
	require.NoError(t, err)
	sshConn, chans, reqs, err := ssh.NewClientConn(tcpConn, server.listener.Addr().String(),
		&ssh.ClientConfig{User: "e2e", HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	require.NoError(t, err)
	master := sshNewClient(sshConn, chans, reqs)
	t.Cleanup(func() { _ = master.Close() })
	m, socket := newTestMuxMaster(t, master, terminate)
	return server, m, socket
}

func TestOpenSSHClientSessions(t *testing.T) {
	sshPath := opensshPath(t)
	server, m, socket := startTcpMuxMaster(t, nil)

	stdout, stderr, code := runOpenSSH(t, sshPath, socket, "", "dummy", "hostname")
	assert.Equal(t, 0, code, stderr)
	assert.Equal(t, "ran: hostname\n", stdout)

	_, stderr, code = runOpenSSH(t, sshPath, socket, "", "dummy", "exit 3")
	assert.Equal(t, 3, code, stderr)

	// all sessions went through the master's single connection
	assert.Equal(t, int32(1), server.handshakes.Load())
	assert.Equal(t, int32(2), server.sessions.Load())
	waitFor(t, "no clients", func() bool { return m.clientCount() == 0 })

	_, stderr, code = runOpenSSH(t, sshPath, socket, "", "-O", "check", "dummy")
	assert.Equal(t, 0, code)
	assert.Contains(t, stderr, "Master running (pid="+strconv.Itoa(os.Getpid())+")")
}

func TestOpenSSHClientForwards(t *testing.T) {
	sshPath := opensshPath(t)
	terminated := make(chan struct{}, 1)
	_, _, socket := startTcpMuxMaster(t, func() { terminated <- struct{}{} })
	echoAddr := startTestEchoServer(t)

	// -W: stdio forwarding through the master
	stdout, stderr, code := runOpenSSH(t, sshPath, socket, "ping through -W", "-W", echoAddr, "dummy")
	assert.Equal(t, 0, code, stderr)
	assert.Equal(t, "ping through -W", stdout)

	// -O forward / -O cancel: a local forwarding owned by the master
	port := freeLocalPort(t)
	forward := "127.0.0.1:" + strconv.Itoa(port) + ":" + echoAddr
	_, stderr, code = runOpenSSH(t, sshPath, socket, "", "-O", "forward", "-L", forward, "dummy")
	assert.Equal(t, 0, code, stderr)
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), time.Second)
	require.NoError(t, err)
	_, err = conn.Write([]byte("via forward"))
	require.NoError(t, err)
	assert.Equal(t, "via forward", readAllWithTimeout(t, conn, 11))
	_ = conn.Close()

	_, stderr, code = runOpenSSH(t, sshPath, socket, "", "-O", "cancel", "-L", forward, "dummy")
	assert.Equal(t, 0, code, stderr)
	_, err = net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 500*time.Millisecond)
	assert.Error(t, err, "forwarding must be closed after cancel")

	// -O exit terminates the master
	_, stderr, code = runOpenSSH(t, sshPath, socket, "", "-O", "exit", "dummy")
	assert.Equal(t, 0, code, stderr)
	select {
	case <-terminated:
	case <-time.After(5 * time.Second):
		t.Fatal("exit request did not terminate the master")
	}
}

// The tests below turn it around: tssh is the client of a real OpenSSH master (`ssh -M`),
// so our side of the mux protocol is checked against OpenSSH and not only against itself.

// startOpenSSHMaster runs `ssh -M -N` against the loopback ssh server and returns its control socket.
func startOpenSSHMaster(t *testing.T, sshPath string, server *testSshServer) (string, *exec.Cmd) {
	t.Helper()
	// keep the socket path short: unix socket paths are limited to ~104 bytes on macOS
	dir, err := os.MkdirTemp("", "tsshmux")
	require.NoError(t, err)
	socket := filepath.Join(dir, "ctl")
	_, port, err := net.SplitHostPort(server.listener.Addr().String())
	require.NoError(t, err)

	cmd := exec.Command(sshPath, "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-M", "-N", "-S", socket, "-p", port, "e2e@127.0.0.1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	require.NoError(t, cmd.Start())
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-exited
		_ = os.RemoveAll(dir)
	})

	deadline := time.Now().Add(10 * time.Second)
	for !isFileExist(socket) {
		select {
		case <-exited:
			t.Fatalf("ssh master exited: %s", stderr.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("ssh master did not create its control socket: %s", stderr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	return socket, cmd
}

func TestTsshPassengerOfOpenSSHMaster(t *testing.T) {
	sshPath := opensshPath(t)
	server := startTestSshServer(t)
	socket, _ := startOpenSSHMaster(t, sshPath, server)
	oriUserConfig := userConfig
	userConfig = &tsshConfig{}
	defer func() { userConfig = oriUserConfig }()

	oriStdin, oriStdout, oriStderr := os.Stdin, os.Stdout, os.Stderr
	files := newPassengerFiles(t)
	os.Stdin, os.Stdout, os.Stderr = files.stdin, files.stdout, files.stderr
	defer func() { os.Stdin, os.Stdout, os.Stderr = oriStdin, oriStdout, oriStderr }()
	_ = files.stdinW.Close() // the remote command gets EOF on stdin

	run := func(command string, options map[string][]string) (int, bool) {
		args := &sshArgs{Destination: "e2e-target", Command: command, ControlPath: socket,
			Option: sshOption{options: options}}
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
		select {
		case r := <-done:
			return r.code, r.handled
		case <-time.After(10 * time.Second):
			t.Fatalf("passenger [%s] did not finish", command)
			return 0, false
		}
	}
	trzszOff := map[string][]string{"controlmaster": {"no"}, "enabletrzsz": {"no"}}

	// with trzsz off the OpenSSH master runs the session on our files
	code, handled := run("hostname", trzszOff)
	assert.True(t, handled)
	assert.Equal(t, 0, code)
	assert.Equal(t, "ran: hostname\n", readAllWithTimeout(t, files.stdoutR, len("ran: hostname\n")))

	code, handled = run("exit 3", trzszOff)
	assert.True(t, handled)
	assert.Equal(t, 3, code)

	// all sessions went through the master's single connection
	assert.Equal(t, int32(1), server.handshakes.Load())
	assert.Equal(t, int32(2), server.sessions.Load())

	// trzsz needs the session output in this process, so tssh does not hand over its terminal
	_, handled = run("hostname", map[string][]string{"controlmaster": {"no"}})
	assert.False(t, handled)
	assert.Equal(t, int32(2), server.sessions.Load())
}

func TestTsshMuxRequestsToOpenSSHMaster(t *testing.T) {
	sshPath := opensshPath(t)
	server := startTestSshServer(t)
	socket, master := startOpenSSHMaster(t, sshPath, server)
	echoAddr := startTestEchoServer(t)
	echoHost, echoPortStr, err := net.SplitHostPort(echoAddr)
	require.NoError(t, err)
	echoPort, err := strconv.Atoi(echoPortStr)
	require.NoError(t, err)

	mc, err := dialMuxMaster(socket, time.Second)
	require.NoError(t, err)
	defer mc.close()
	assert.False(t, mc.tsshMaster, "an OpenSSH master has no tssh hello extension")
	pid, err := mc.aliveCheck()
	require.NoError(t, err)
	assert.Equal(t, uint32(master.Process.Pid), pid)

	// -L: a local forwarding owned by the master
	port := freeLocalPort(t)
	fwd := &muxForwardRequest{ftype: kMuxFwdLocal, listenHost: "127.0.0.1", listenPort: uint32(port),
		connectHost: echoHost, connectPort: uint32(echoPort)}
	_, err = mc.openForward(fwd)
	require.NoError(t, err)
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), time.Second)
	require.NoError(t, err)
	_, err = conn.Write([]byte("via forward"))
	require.NoError(t, err)
	assert.Equal(t, "via forward", readAllWithTimeout(t, conn, len("via forward")))
	_ = conn.Close()
	require.NoError(t, mc.closeForward(fwd))
	_, err = net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 500*time.Millisecond)
	assert.Error(t, err, "forwarding must be closed after cancel")

	// -W: stdio forwarding on a connection of its own, like `tssh -W`
	sc, err := dialMuxMaster(socket, time.Second)
	require.NoError(t, err)
	defer sc.close()
	files := newPassengerFiles(t)
	_, err = sc.stdioForward(echoHost, uint32(echoPort), files.stdin, files.stdout)
	require.NoError(t, err)
	_, err = files.stdinW.Write([]byte("through -W"))
	require.NoError(t, err)
	assert.Equal(t, "through -W", readAllWithTimeout(t, files.stdoutR, len("through -W")))

	// -O exit: the master goes away
	assert.Equal(t, 0, muxControlCommand(socket, "exit"))
	waitFor(t, "master exit", func() bool { return !isFileExist(socket) })
}

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

// startTcpMuxMaster logs in to the loopback ssh server and serves a control socket for it.
func startTcpMuxMaster(t *testing.T) (*testSshServer, *muxMaster, string) {
	t.Helper()
	server := startTestSshServer(t)
	tcpConn, err := net.DialTimeout("tcp", server.listener.Addr().String(), 5*time.Second)
	require.NoError(t, err)
	sshConn, chans, reqs, err := ssh.NewClientConn(tcpConn, server.listener.Addr().String(),
		&ssh.ClientConfig{User: "e2e", HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	require.NoError(t, err)
	master := sshNewClient(sshConn, chans, reqs)
	t.Cleanup(func() { _ = master.Close() })
	m, socket := newTestMuxMaster(t, master)
	return server, m, socket
}

func TestOpenSSHClientSessions(t *testing.T) {
	sshPath := opensshPath(t)
	server, m, socket := startTcpMuxMaster(t)

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
	_, m, socket := startTcpMuxMaster(t)
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
	terminated := make(chan struct{}, 1)
	m.setTerminate(func() { terminated <- struct{}{} })
	_, stderr, code = runOpenSSH(t, sshPath, socket, "", "-O", "exit", "dummy")
	assert.Equal(t, 0, code, stderr)
	select {
	case <-terminated:
	case <-time.After(5 * time.Second):
		t.Fatal("exit request did not terminate the master")
	}
}

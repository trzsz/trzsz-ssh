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
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// testSshServer is a minimal ssh server listening on a loopback port. It counts
// transport connections and session channels, which is how the test proves that
// all multiplexed clients share the master's single connection.
type testSshServer struct {
	listener   net.Listener
	handshakes atomic.Int32
	sessions   atomic.Int32
}

func startTestSshServer(t *testing.T) *testSshServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	s := &testSshServer{listener: listener}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go s.handleConn(conn, config)
		}
	}()
	return s
}

func (s *testSshServer) handleConn(conn net.Conn, config *ssh.ServerConfig) {
	sconn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		_ = conn.Close()
		return
	}
	defer func() { _ = sconn.Close() }()
	s.handshakes.Add(1)
	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		switch newChannel.ChannelType() {
		case "session":
			s.sessions.Add(1)
			channel, requests, err := newChannel.Accept()
			if err != nil {
				continue
			}
			go s.handleSession(channel, requests)
		case "direct-tcpip":
			var payload sshDirectTcpipPayload
			if err := ssh.Unmarshal(newChannel.ExtraData(), &payload); err != nil {
				_ = newChannel.Reject(ssh.ConnectionFailed, err.Error())
				continue
			}
			target, err := net.Dial("tcp", net.JoinHostPort(payload.RAddr, strconv.Itoa(int(payload.RPort))))
			if err != nil {
				_ = newChannel.Reject(ssh.ConnectionFailed, err.Error())
				continue
			}
			channel, requests, err := newChannel.Accept()
			if err != nil {
				_ = target.Close()
				continue
			}
			go ssh.DiscardRequests(requests)
			go func() {
				_, _ = io.Copy(channel, target)
				_ = channel.Close()
			}()
			go func() {
				_, _ = io.Copy(target, channel)
				_ = target.Close()
			}()
		default:
			_ = newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}
}

// handleSession answers an exec request with "ran: <command>" and exit status 0.
func (s *testSshServer) handleSession(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer func() { _ = channel.Close() }()
	for req := range requests {
		switch req.Type {
		case "exec":
			var payload sshExecPayload
			if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
				_ = req.Reply(false, nil)
				return
			}
			_ = req.Reply(true, nil)
			_, _ = fmt.Fprintf(channel, "ran: %s\n", payload.Command)
			_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(&sshExitStatusPayload{Status: 0}))
			return
		case "pty-req", "env":
			_ = req.Reply(true, nil)
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

// startTestEchoServer returns the address of a tcp echo server used as a forwarding target.
func startTestEchoServer(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(conn, conn)
				_ = conn.Close()
			}()
		}
	}()
	return listener.Addr().String()
}

func runCommand(t *testing.T, client SshClient, cmd string) string {
	t.Helper()
	session, err := client.NewSession()
	require.NoError(t, err)
	defer func() { _ = session.Close() }()
	output, err := session.Output(cmd)
	require.NoError(t, err)
	return string(output)
}

// TestMuxEndToEnd runs a master against a real ssh server on a loopback port, attaches
// slaves through the control socket with the production login code, and verifies that
// the server saw exactly one connection carrying all sessions.
func TestMuxEndToEnd(t *testing.T) {
	server := startTestSshServer(t)
	echoAddr := startTestEchoServer(t)

	// the master logs in over tcp and starts serving the control socket
	tcpConn, err := net.DialTimeout("tcp", server.listener.Addr().String(), 5*time.Second)
	require.NoError(t, err)
	sshConn, chans, reqs, err := ssh.NewClientConn(tcpConn, server.listener.Addr().String(),
		&ssh.ClientConfig{User: "e2e", HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	require.NoError(t, err)
	master := sshNewClient(sshConn, chans, reqs)
	defer func() { _ = master.Close() }()
	assert.Equal(t, "ran: master\n", runCommand(t, master, "master"))

	m, socket := newTestMuxMaster(t, master)
	terminated := make(chan struct{}, 1)
	m.terminate = func() { terminated <- struct{}{} }

	// slaves attach through connectViaControl, the same code path as `tssh -S <socket>`
	const slaveCount = 3
	slaves := make([]SshClient, 0, slaveCount)
	for i := 0; i < slaveCount; i++ {
		args := &sshArgs{
			Destination: "e2e-target",
			ControlPath: socket,
			Option:      sshOption{options: map[string][]string{"controlmaster": {"no"}}},
		}
		param := &sshParam{args: args, host: "127.0.0.1", port: "22", user: "e2e", udpMode: kUdpModeYes}
		client := connectViaControl(param)
		require.NotNil(t, client, "slave %d failed to attach to the control socket", i)
		defer func() { _ = client.Close() }()
		assert.True(t, param.controlUdp, "slave %d did not recognize the tssh udp master", i)
		slaves = append(slaves, client)

		cmd := fmt.Sprintf("slave-%d", i)
		assert.Equal(t, "ran: "+cmd+"\n", runCommand(t, client, cmd))
	}

	// a local forward through a slave is dialed by the master's connection
	fwd, err := slaves[0].DialTimeout("tcp", echoAddr, 5*time.Second)
	require.NoError(t, err)
	_, err = fwd.Write([]byte("through the master"))
	require.NoError(t, err)
	buf := make([]byte, len("through the master"))
	_, err = io.ReadFull(fwd, buf)
	require.NoError(t, err)
	assert.Equal(t, "through the master", string(buf))
	_ = fwd.Close()

	// one transport connection, one session per client
	assert.Equal(t, int32(1), server.handshakes.Load(), "slaves must not open their own connections")
	assert.Equal(t, int32(1+slaveCount), server.sessions.Load())
	for i, slave := range slaves {
		wrapper, ok := slave.(*sshClientWrapper)
		require.True(t, ok)
		assert.Equal(t, "unix", wrapper.client.RemoteAddr().Network(), "slave %d is not connected via the control socket", i)
	}
	assert.Equal(t, slaveCount, m.clientCount())

	// control commands
	assert.Equal(t, 0, muxControlCommand(socket, "check"))
	assert.Equal(t, 0, muxControlCommand(socket, "exit"))
	select {
	case <-terminated:
	case <-time.After(5 * time.Second):
		t.Fatal("exit request did not terminate the master")
	}

	for _, slave := range slaves {
		_ = slave.Close()
	}
	waitFor(t, "slaves disconnected", func() bool { return m.clientCount() == 0 })
	assert.Equal(t, int32(1), server.handshakes.Load())
}

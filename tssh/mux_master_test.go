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
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func newTestMuxMaster(t *testing.T, backend SshClient) (*muxMaster, string) {
	t.Helper()
	// keep the socket path short: unix socket paths are limited to ~104 bytes on macOS
	dir, err := os.MkdirTemp("", "tsshmux")
	require.NoError(t, err)
	socket := filepath.Join(dir, "ctl")
	param := &sshParam{args: &sshArgs{}}
	param.args.Destination = "test-host"
	m, err := startMuxMaster(param, backend, socket)
	require.NoError(t, err)
	t.Cleanup(func() {
		m.close()
		_ = os.RemoveAll(dir)
		muxMastersMu.Lock()
		muxMasters = nil
		muxMastersMu.Unlock()
	})
	return m, socket
}

func TestMuxMasterSocketPermissions(t *testing.T) {
	_, socket := newTestMuxMaster(t, newFakeSshClient())
	info, err := os.Stat(socket)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	assert.True(t, info.Mode()&os.ModeSocket != 0)
}

func TestMuxMasterProxyClientSession(t *testing.T) {
	backend := newFakeSshClient()
	m, socket := newTestMuxMaster(t, backend)

	conn, err := net.DialTimeout("unix", socket, time.Second)
	require.NoError(t, err)
	ncc, chans, reqs, err := ssh.NewControlClientConn(conn)
	require.NoError(t, err)
	client := sshNewClient(ncc, chans, reqs)
	defer func() { _ = client.Close() }()

	assert.True(t, isUdpMuxMaster(client))
	waitFor(t, "one proxy client", func() bool { return m.clientCount() == 1 })

	sess, err := client.NewSession()
	require.NoError(t, err)
	stdout, err := sess.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, sess.Start("uname"))

	fs := backend.session(0)
	require.NotNil(t, fs)
	fs.waitStarted(t)
	assert.Equal(t, "uname", fs.cmd)
	_, err = fs.stdoutW.Write([]byte("Darwin\n"))
	require.NoError(t, err)
	fs.finish(0)

	var out bytes.Buffer
	_, err = out.ReadFrom(stdout)
	require.NoError(t, err)
	require.NoError(t, sess.Wait())
	assert.Equal(t, "Darwin\n", out.String())

	require.NoError(t, client.Close())
	waitFor(t, "no proxy clients", func() bool { return m.clientCount() == 0 })
	assert.Equal(t, 0, muxMastersClientCount())
}

func TestMuxMasterControlCommands(t *testing.T) {
	backend := newFakeSshClient()
	m, socket := newTestMuxMaster(t, backend)
	terminated := make(chan struct{}, 1)
	m.terminate = func() { terminated <- struct{}{} }

	assert.Equal(t, 0, muxControlCommand(socket, "check"))
	assert.Equal(t, kExitCodeToolsError, muxControlCommand(socket, "bogus"))

	// a connected proxy client survives `stop`
	conn, err := net.DialTimeout("unix", socket, time.Second)
	require.NoError(t, err)
	ncc, chans, reqs, err := ssh.NewControlClientConn(conn)
	require.NoError(t, err)
	client := sshNewClient(ncc, chans, reqs)
	defer func() { _ = client.Close() }()

	assert.Equal(t, 0, muxControlCommand(socket, "stop"))
	waitFor(t, "socket removed", func() bool { return !isFileExist(socket) })
	assert.Equal(t, kExitCodeToolsError, muxControlCommand(socket, "check"))
	ok, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
	require.NoError(t, err)
	assert.True(t, ok)

	// exit goes through a fresh master
	m2, socket2 := newTestMuxMaster(t, backend)
	m2.terminate = m.terminate
	assert.Equal(t, 0, muxControlCommand(socket2, "exit"))
	select {
	case <-terminated:
	case <-time.After(5 * time.Second):
		t.Fatal("terminate not called")
	}
}

func TestMuxMasterRejectsPassengerAndBadHello(t *testing.T) {
	_, socket := newTestMuxMaster(t, newFakeSshClient())

	// passenger mode (MUX_C_NEW_SESSION) is refused with a reason
	conn, err := net.DialTimeout("unix", socket, time.Second)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.NoError(t, muxClientHello(conn))
	require.NoError(t, muxWriteMessage(conn, kMuxCNewSession, uint32(7), "", uint32(0)))
	msgType, body, err := muxReadMessage(conn)
	require.NoError(t, err)
	assert.Equal(t, kMuxSFailure, msgType)
	rid, ok := muxReadUint32(&body)
	require.True(t, ok)
	assert.Equal(t, uint32(7), rid)
	reason, ok := muxReadString(&body)
	require.True(t, ok)
	assert.Contains(t, reason, "proxy mode")

	// wrong protocol version closes the connection
	conn2, err := net.DialTimeout("unix", socket, time.Second)
	require.NoError(t, err)
	defer func() { _ = conn2.Close() }()
	require.NoError(t, muxWriteMessage(conn2, kMuxMsgHello, uint32(3)))
	_ = conn2.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _, err = muxReadMessage(conn2)
	assert.Error(t, err)
}

func TestRemoveStaleMuxSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "tsshmux")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(dir) }()
	socket := filepath.Join(dir, "ctl")

	assert.False(t, removeStaleMuxSocket(socket))

	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	assert.False(t, removeStaleMuxSocket(socket)) // alive
	_ = listener.Close()                          // Go unlinks the socket on Close

	// recreate a dead socket file
	listener, err = net.Listen("unix", socket)
	require.NoError(t, err)
	if ul, ok := listener.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	_ = listener.Close()
	require.True(t, isFileExist(socket))
	assert.True(t, removeStaleMuxSocket(socket))
	assert.False(t, isFileExist(socket))
}

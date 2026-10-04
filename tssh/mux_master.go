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
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// muxMaster is a native multiplexing master: it listens on the ControlPath unix socket
// and serves OpenSSH mux protocol clients on top of one SshClient (the UDP client).
type muxMaster struct {
	socket    string
	listener  net.Listener
	client    SshClient
	terminate func()

	connMu   sync.Mutex
	connCond *sync.Cond
	conns    map[*muxProxyConn]struct{}

	listening atomic.Bool
	closed    atomic.Bool
}

// kMaxUnixSocketPath is the size of sockaddr_un.sun_path (104 on BSD/macOS, 108 on Linux).
const kMaxUnixSocketPath = len(syscall.RawSockaddrUnix{}.Path)

var muxMastersMu sync.Mutex
var muxMasters []*muxMaster

// startMuxMaster creates the control socket and starts serving mux clients.
func startMuxMaster(param *sshParam, client SshClient, socket string) (*muxMaster, error) {
	oldMask := syscall.Umask(0177)
	listener, err := net.Listen("unix", socket)
	syscall.Umask(oldMask)
	if err != nil {
		if len(socket) >= kMaxUnixSocketPath {
			return nil, fmt.Errorf("listen on control socket [%s] failed: %v (ControlPath too long, max %d bytes)",
				socket, err, kMaxUnixSocketPath-1)
		}
		return nil, fmt.Errorf("listen on control socket [%s] failed: %v", socket, err)
	}
	_ = os.Chmod(socket, 0600)

	m := &muxMaster{
		socket:   socket,
		listener: listener,
		client:   client,
		conns:    make(map[*muxProxyConn]struct{}),
	}
	m.connCond = sync.NewCond(&m.connMu)
	m.listening.Store(true)
	m.terminate = func() { terminateMuxMaster(client) }

	muxMastersMu.Lock()
	muxMasters = append(muxMasters, m)
	muxMastersMu.Unlock()

	addOnCloseFunc(m.close)
	addOnExitFunc(m.removeSocket)

	go m.serve()
	debug("control master listening on [%s] for [%s]", socket, param.args.Destination)
	return m, nil
}

// terminateMuxMaster exits the master process after a MUX_C_TERMINATE request.
func terminateMuxMaster(client SshClient) {
	if udpClient, ok := client.(*sshUdpClient); ok {
		if sshConn := udpClient.sshConn.Load(); sshConn != nil {
			sshConn.forceExit(0, "control master terminated by control command")
			return
		}
	}
	wantExit.Store(true)
	_ = client.Close()
}

func (m *muxMaster) serve() {
	for {
		conn, err := m.listener.Accept()
		if err != nil {
			if m.listening.Load() && !m.closed.Load() && !errors.Is(err, net.ErrClosed) {
				warning("control master accept failed: %v", err)
			}
			return
		}
		go m.handleConn(conn)
	}
}

func (m *muxMaster) handleConn(conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(kMuxHandshakeTimeout))
	if err := muxServerHello(conn); err != nil {
		debug("control master handshake failed: %v", err)
		_ = conn.Close()
		return
	}
	writer := &muxPacketWriter{w: conn}
	for {
		msgType, body, err := muxReadMessage(conn)
		if err != nil {
			_ = conn.Close()
			return
		}
		rid, ok := muxReadUint32(&body)
		if !ok {
			_ = conn.Close()
			return
		}
		switch msgType {
		case kMuxCAliveCheck:
			err = writer.writeMuxMessage(kMuxSAlive, rid, uint32(os.Getpid()))
		case kMuxCTerminate:
			_ = writer.writeMuxMessage(kMuxSOk, rid)
			_ = conn.Close()
			debug("control master received terminate request")
			m.terminate()
			return
		case kMuxCStopListening:
			m.stopListening()
			err = writer.writeMuxMessage(kMuxSOk, rid)
		case kMuxCProxy:
			if err := writer.writeMuxMessage(kMuxSProxy, rid); err != nil {
				_ = conn.Close()
				return
			}
			_ = conn.SetDeadline(time.Time{})
			m.serveProxy(conn)
			return
		case kMuxCNewSession, kMuxCNewStdioFwd, kMuxCOpenFwd, kMuxCCloseFwd:
			// passenger mode (fd passing) is not implemented; only tssh clients (proxy mode) are supported
			err = writer.writeMuxMessage(kMuxSFailure, rid,
				"tssh udp control master only supports proxy mode clients, please use tssh instead of ssh")
		default:
			err = writer.writeMuxMessage(kMuxSFailure, rid, fmt.Sprintf("unsupported mux request type 0x%08x", msgType))
		}
		if err != nil {
			_ = conn.Close()
			return
		}
	}
}

func (m *muxMaster) serveProxy(conn net.Conn) {
	var pc *muxProxyConn
	pc = newMuxProxyConn(conn, m.client, func() { m.removeConn(pc) })
	m.connMu.Lock()
	if m.closed.Load() {
		m.connMu.Unlock()
		_ = conn.Close()
		return
	}
	m.conns[pc] = struct{}{}
	m.connMu.Unlock()
	debug("control master accepted a proxy client")
	pc.serve()
	debug("control master proxy client disconnected")
}

func (m *muxMaster) removeConn(pc *muxProxyConn) {
	m.connMu.Lock()
	delete(m.conns, pc)
	m.connCond.Broadcast()
	m.connMu.Unlock()
}

func (m *muxMaster) clientCount() int {
	m.connMu.Lock()
	defer m.connMu.Unlock()
	return len(m.conns)
}

// stopListening closes the control socket; already connected clients keep running.
func (m *muxMaster) stopListening() {
	if !m.listening.CompareAndSwap(true, false) {
		return
	}
	_ = m.listener.Close()
	m.removeSocket()
	debug("control master stopped listening on [%s]", m.socket)
}

func (m *muxMaster) removeSocket() {
	if err := os.Remove(m.socket); err != nil && !errors.Is(err, os.ErrNotExist) {
		debug("remove control socket [%s] failed: %v", m.socket, err)
	}
}

// close stops listening and disconnects every client.
func (m *muxMaster) close() {
	if !m.closed.CompareAndSwap(false, true) {
		return
	}
	m.stopListening()
	m.connMu.Lock()
	conns := make([]*muxProxyConn, 0, len(m.conns))
	for pc := range m.conns {
		conns = append(conns, pc)
	}
	m.connCond.Broadcast()
	m.connMu.Unlock()
	for _, pc := range conns {
		pc.close()
	}
}

// waitClients blocks until no proxy client is connected or the master is closed.
func (m *muxMaster) waitClients() {
	m.connMu.Lock()
	defer m.connMu.Unlock()
	for len(m.conns) > 0 && !m.closed.Load() {
		m.connCond.Wait()
	}
}

// muxMastersClientCount returns the number of clients connected to all masters of this process.
func muxMastersClientCount() int {
	muxMastersMu.Lock()
	masters := append([]*muxMaster(nil), muxMasters...)
	muxMastersMu.Unlock()
	count := 0
	for _, m := range masters {
		count += m.clientCount()
	}
	return count
}

// waitMuxMastersIdle waits until the multiplexed clients of this process have all disconnected.
func waitMuxMastersIdle() {
	muxMastersMu.Lock()
	masters := append([]*muxMaster(nil), muxMasters...)
	muxMastersMu.Unlock()
	for _, m := range masters {
		m.waitClients()
	}
}

// waitMuxMasterClients keeps the master process alive after its own session ended
// until every multiplexed client has disconnected (Ctrl+C still forces the exit).
func waitMuxMasterClients(sshConn *sshConnection, rawState *stdinState) {
	if sshConn.exited.Load() {
		return
	}
	count := muxMastersClientCount()
	if count == 0 {
		return
	}
	if rawState != nil {
		resetStdin(rawState)
	}
	warning("control master: %d multiplexed client(s) still connected, waiting for them to exit (press Ctrl+C to force exit)", count)
	waitMuxMastersIdle()
	debug("control master: all multiplexed clients exited")
}

// removeStaleMuxSocket removes a control socket nobody is listening on. It returns true if removed.
func removeStaleMuxSocket(socket string) bool {
	if !isFileExist(socket) {
		return false
	}
	conn, err := net.DialTimeout("unix", socket, 500*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return false
	}
	if !errors.Is(err, syscall.ECONNREFUSED) && !errors.Is(err, syscall.ENOENT) {
		return false
	}
	if err := os.Remove(socket); err != nil {
		return false
	}
	debug("removed stale control socket [%s]", socket)
	return true
}

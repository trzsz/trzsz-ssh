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
	"os/signal"
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
	param     *sshParam
	sshConn   atomic.Pointer[sshConnection]
	terminate atomic.Pointer[func()]

	connMu   sync.Mutex
	connCond *sync.Cond
	conns    map[*muxProxyConn]struct{}

	passengerSeq atomic.Uint32
	passengers   map[uint32]*muxPassenger

	fwdMu    sync.Mutex
	forwards map[string][]net.Listener

	agentOnce      sync.Once
	agentForwarded bool

	listening atomic.Bool
	closed    atomic.Bool
	done      chan struct{}

	sockCleanup func() (bool, error)
}

// kMaxUnixSocketPath is the size of sockaddr_un.sun_path (104 on BSD/macOS, 108 on Linux).
const kMaxUnixSocketPath = len(syscall.RawSockaddrUnix{}.Path)

var muxMastersMu sync.Mutex
var muxMasters []*muxMaster

// startMuxMaster creates the control socket and starts serving mux clients.
func startMuxMaster(param *sshParam, client SshClient, socket string) (*muxMaster, error) {
	listener, err := net.Listen("unix", socket)
	if err != nil {
		if len(socket) >= kMaxUnixSocketPath {
			return nil, fmt.Errorf("listen on control socket [%s] failed: %v (ControlPath too long, max %d bytes)",
				socket, err, kMaxUnixSocketPath-1)
		}
		return nil, fmt.Errorf("listen on control socket [%s] failed: %v", socket, err)
	}
	if err := os.Chmod(socket, 0600); err != nil {
		_ = listener.Close()
		_ = os.Remove(socket)
		return nil, fmt.Errorf("chmod on control socket [%s] failed: %v", socket, err)
	}

	m := &muxMaster{
		socket:      socket,
		listener:    listener,
		client:      client,
		param:       param,
		conns:       make(map[*muxProxyConn]struct{}),
		passengers:  make(map[uint32]*muxPassenger),
		forwards:    make(map[string][]net.Listener),
		done:        make(chan struct{}),
		sockCleanup: newFileUnlinker(socket, listener),
	}
	m.connCond = sync.NewCond(&m.connMu)
	m.listening.Store(true)
	m.setTerminate(m.terminateProcess)

	muxMastersMu.Lock()
	muxMasters = append(muxMasters, m)
	muxMastersMu.Unlock()

	addOnCloseFunc(m.close)
	addOnExitFunc(func() { _, _ = m.sockCleanup() })

	go m.serve()
	go m.watchWindowChanges()
	debug("control master listening on [%s] for [%s]", socket, param.args.Destination)
	return m, nil
}

// setTerminate sets the action of a MUX_C_TERMINATE request (tests replace the process exit).
func (m *muxMaster) setTerminate(fn func()) {
	m.terminate.Store(&fn)
}

// terminateProcess exits the master process after a MUX_C_TERMINATE request.
func (m *muxMaster) terminateProcess() {
	// When any hop exits, the entire link becomes unusable, meaning all hops must exit together.
	// In UDP mode, we must explicitly force the last-hop UDP connection to exit;
	// otherwise, it may continuously attempt to reconnect.

	// Wait up to 10 seconds for sshConn to be initialized
	for range 1000 {
		if m.sshConn.Load() != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if sshConn := m.sshConn.Load(); sshConn != nil {
		sshConn.forceExit(kExitCodeMasterExit, "control master terminated by control command")
		return
	}
	warning("should not reach here, possible bug, control master has no ssh connection")
	wantExit.Store(true)
	_ = m.client.Close()
}

// setMuxMastersConnection lets the masters of this process exit through the ssh connection.
func setMuxMastersConnection(sshConn *sshConnection) {
	muxMastersMu.Lock()
	defer muxMastersMu.Unlock()
	for _, m := range muxMasters {
		m.sshConn.Store(sshConn)
	}
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
			(*m.terminate.Load())()
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
		case kMuxCNewSession:
			unixConn, ok := conn.(*net.UnixConn)
			if !ok {
				err = writer.writeMuxMessage(kMuxSFailure, rid, "passenger mode requires a unix socket")
				break
			}
			m.handleNewSession(unixConn, writer, rid, body)
			return
		case kMuxCNewStdioFwd:
			unixConn, ok := conn.(*net.UnixConn)
			if !ok {
				err = writer.writeMuxMessage(kMuxSFailure, rid, "stdio forwarding requires a unix socket")
				break
			}
			m.handleStdioForward(unixConn, writer, rid, body)
			return
		case kMuxCOpenFwd:
			err = m.handleOpenForward(writer, rid, body)
		case kMuxCCloseFwd:
			err = m.handleCloseForward(writer, rid, body)
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

func (m *muxMaster) addPassenger(p *muxPassenger) {
	m.connMu.Lock()
	m.passengers[p.id] = p
	m.connMu.Unlock()
}

func (m *muxMaster) removePassenger(p *muxPassenger) {
	m.connMu.Lock()
	delete(m.passengers, p.id)
	m.connCond.Broadcast()
	m.connMu.Unlock()
}

// clientCount returns the number of connected proxy and passenger clients.
func (m *muxMaster) clientCount() int {
	m.connMu.Lock()
	defer m.connMu.Unlock()
	return len(m.conns) + len(m.passengers)
}

// watchWindowChanges propagates terminal size changes to the passengers. A passenger
// client relays its SIGWINCH to the master process, so the sizes are re-read on every signal.
func (m *muxMaster) watchWindowChanges() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	defer signal.Stop(ch)
	for {
		select {
		case <-ch:
		case <-m.done:
			return
		}
		m.connMu.Lock()
		passengers := make([]*muxPassenger, 0, len(m.passengers))
		for _, p := range m.passengers {
			passengers = append(passengers, p)
		}
		m.connMu.Unlock()
		for _, p := range passengers {
			p.checkWindowChange()
		}
	}
}

// stopListening closes the control socket; already connected clients keep running.
func (m *muxMaster) stopListening() {
	if !m.listening.CompareAndSwap(true, false) {
		return
	}
	_, _ = m.sockCleanup()
	debug("control master stopped listening on [%s]", m.socket)
}

// close stops listening and disconnects every client.
func (m *muxMaster) close() {
	if !m.closed.CompareAndSwap(false, true) {
		return
	}
	m.stopListening()
	close(m.done)
	m.connMu.Lock()
	conns := make([]*muxProxyConn, 0, len(m.conns))
	for pc := range m.conns {
		conns = append(conns, pc)
	}
	passengers := make([]*muxPassenger, 0, len(m.passengers))
	for _, p := range m.passengers {
		passengers = append(passengers, p)
	}
	m.connCond.Broadcast()
	m.connMu.Unlock()
	for _, pc := range conns {
		pc.close()
	}
	for _, p := range passengers {
		p.close()
	}
	m.closeForwards()
}

// waitClients blocks until no proxy client is connected or the master is closed.
func (m *muxMaster) waitClients() {
	m.connMu.Lock()
	defer m.connMu.Unlock()
	for len(m.conns)+len(m.passengers) > 0 && !m.closed.Load() {
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
func waitMuxMasterClients(sshConn *sshConnection) {
	if sshConn.exited.Load() {
		return
	}
	count := muxMastersClientCount()
	if count == 0 {
		return
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
	unlinker := newFileUnlinker(socket, nil)
	conn, err := net.DialTimeout("unix", socket, 500*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return false
	}
	if !errors.Is(err, syscall.ECONNREFUSED) && !errors.Is(err, syscall.ENOENT) {
		return false
	}
	if removed, _ := unlinker(); !removed {
		return false
	}
	debug("removed stale control socket [%s]", socket)
	return true
}

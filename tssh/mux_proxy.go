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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// This file implements the master side of the OpenSSH multiplexing "proxy mode":
// after the mux handshake the client speaks the plain ssh connection protocol
// (channels, global requests) over the control socket, without any encryption.
// Each incoming ssh channel is mapped onto the master's SshClient (e.g. the UDP
// client of tsshd), so multiple tssh processes share one transport.

const (
	kMuxDefaultDialTimeout = 10 * time.Second
	kMuxOpenReplyTimeout   = 30 * time.Second
	kMuxOutputDrainTimeout = 2 * time.Second
)

var errMuxConnClosed = errors.New("mux connection closed")

// muxServerHello performs the master side of the mux HELLO exchange.
func muxServerHello(rw io.ReadWriter) error {
	msgType, body, err := muxReadMessage(rw)
	if err != nil {
		return fmt.Errorf("read mux hello failed: %w", err)
	}
	if msgType != kMuxMsgHello {
		return fmt.Errorf("expected mux hello, got 0x%08x", msgType)
	}
	version, ok := muxReadUint32(&body)
	if !ok {
		return fmt.Errorf("mux hello missing protocol version")
	}
	if version != kMuxProtocolVersion {
		return fmt.Errorf("unsupported mux protocol version %d", version)
	}
	// extension name/value pairs are ignored
	if err := muxWriteMessage(rw, kMuxMsgHello, kMuxProtocolVersion); err != nil {
		return fmt.Errorf("write mux hello failed: %w", err)
	}
	return nil
}

// muxAcceptProxyHandshake performs the HELLO exchange and expects a MUX_C_PROXY request,
// which it confirms with MUX_S_PROXY. Afterwards the connection carries ssh packets.
func muxAcceptProxyHandshake(rw io.ReadWriter) error {
	if err := muxServerHello(rw); err != nil {
		return err
	}
	msgType, body, err := muxReadMessage(rw)
	if err != nil {
		return fmt.Errorf("read mux request failed: %w", err)
	}
	if msgType != kMuxCProxy {
		return fmt.Errorf("expected mux proxy request, got 0x%08x", msgType)
	}
	rid, ok := muxReadUint32(&body)
	if !ok {
		return fmt.Errorf("mux proxy request missing request id")
	}
	if err := muxWriteMessage(rw, kMuxSProxy, rid); err != nil {
		return fmt.Errorf("write mux proxy response failed: %w", err)
	}
	return nil
}

// isUdpMuxMaster probes whether the control master behind client is a tssh UDP master.
// An OpenSSH master forwards the unknown global request to sshd, which rejects it.
func isUdpMuxMaster(client SshClient) bool {
	ok, _, err := client.SendRequest(kMuxUdpModeRequest, true, nil)
	return err == nil && ok
}

// muxWindow tracks how many bytes the peer allows us to send on a channel.
type muxWindow struct {
	mu     sync.Mutex
	cond   *sync.Cond
	avail  uint32
	closed bool
}

func newMuxWindow(initial uint32) *muxWindow {
	w := &muxWindow{avail: initial}
	w.cond = sync.NewCond(&w.mu)
	return w
}

func (w *muxWindow) add(n uint32) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if uint64(w.avail)+uint64(n) > math.MaxUint32 {
		return fmt.Errorf("channel window overflow")
	}
	w.avail += n
	w.cond.Broadcast()
	return nil
}

// reserve blocks until at least one byte is available and returns min(want, available).
func (w *muxWindow) reserve(want uint32) (uint32, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for w.avail == 0 && !w.closed {
		w.cond.Wait()
	}
	if w.closed {
		return 0, errMuxConnClosed
	}
	got := min(want, w.avail)
	w.avail -= got
	return got, nil
}

func (w *muxWindow) close() {
	w.mu.Lock()
	w.closed = true
	w.cond.Broadcast()
	w.mu.Unlock()
}

// muxByteQueue buffers inbound channel data so the packet read loop never blocks on backend writes.
// Memory is bounded by the channel window we grant to the peer.
type muxByteQueue struct {
	mu     sync.Mutex
	cond   *sync.Cond
	items  [][]byte
	eof    bool
	closed bool
}

func newMuxByteQueue() *muxByteQueue {
	q := &muxByteQueue{}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func (q *muxByteQueue) push(data []byte) {
	q.mu.Lock()
	if !q.closed && !q.eof {
		q.items = append(q.items, data)
	}
	q.cond.Broadcast()
	q.mu.Unlock()
}

// markEOF signals that no more data will arrive; pending items are still delivered.
func (q *muxByteQueue) markEOF() {
	q.mu.Lock()
	q.eof = true
	q.cond.Broadcast()
	q.mu.Unlock()
}

// abort drops pending items and wakes the consumer.
func (q *muxByteQueue) abort() {
	q.mu.Lock()
	q.closed = true
	q.items = nil
	q.cond.Broadcast()
	q.mu.Unlock()
}

// pop blocks for the next item; ok is false once the queue is drained after EOF or aborted.
func (q *muxByteQueue) pop() ([]byte, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.items) == 0 && !q.eof && !q.closed {
		q.cond.Wait()
	}
	if q.closed || len(q.items) == 0 {
		return nil, false
	}
	data := q.items[0]
	q.items = q.items[1:]
	return data, true
}

// muxRemoteForward is a remote listener created by a tcpip-forward style global request.
type muxRemoteForward struct {
	key      string
	chanType string
	addr     string // verbatim address from the request, echoed in forwarded channel opens
	port     uint32
	listener net.Listener
}

// muxProxyConn serves one proxy-mode control connection.
type muxProxyConn struct {
	rw          io.ReadWriteCloser
	client      SshClient
	writer      *muxPacketWriter
	dialTimeout time.Duration

	chanMu sync.Mutex
	chans  map[uint32]*muxChannel
	nextID uint32

	fwdMu    sync.Mutex
	forwards map[string]*muxRemoteForward

	closed  atomic.Bool
	done    chan struct{}
	onClose func()
}

// muxChannel is one ssh channel of a proxy connection mapped onto a backend session or stream.
type muxChannel struct {
	conn     *muxProxyConn
	localID  uint32
	remoteID uint32
	chanType string

	remoteWin *muxWindow // bytes we may still send to the peer
	remoteMax uint32     // largest data packet the peer accepts

	winMu    sync.Mutex
	myWindow uint32 // bytes the peer may still send to us
	consumed uint32 // bytes consumed since the last window adjust

	inQueue *muxByteQueue

	// session channels
	session   SshSession
	stdinW    io.WriteCloser
	stdinOnce sync.Once
	stdoutR   io.Reader
	started   atomic.Bool

	// stream channels (direct-tcpip, direct-streamlocal, forwarded-*)
	stream net.Conn

	// server-initiated opens wait here for the peer's confirmation or failure
	openReply chan any

	outWG     sync.WaitGroup
	outDone   atomic.Bool
	gotEOF    atomic.Bool
	sentEOF   atomic.Bool
	sentClose atomic.Bool
	closed    atomic.Bool
	closeOnce sync.Once
}

func newMuxProxyConn(rw io.ReadWriteCloser, client SshClient, onClose func()) *muxProxyConn {
	return &muxProxyConn{
		rw:          rw,
		client:      client,
		writer:      &muxPacketWriter{w: rw},
		dialTimeout: kMuxDefaultDialTimeout,
		chans:       make(map[uint32]*muxChannel),
		forwards:    make(map[string]*muxRemoteForward),
		done:        make(chan struct{}),
		onClose:     onClose,
	}
}

// serve runs the packet read loop until the connection fails or a protocol error occurs.
func (c *muxProxyConn) serve() {
	defer c.close()
	for {
		pkt, err := muxReadSshPacket(c.rw)
		if err != nil {
			if !c.closed.Load() && !errors.Is(err, io.EOF) {
				debug("control master: read from mux client failed: %v", err)
			}
			return
		}
		if err := c.handlePacket(pkt); err != nil {
			warning("control master: mux client protocol error: %v", err)
			return
		}
	}
}

// close tears down every channel and remote forward of this connection.
func (c *muxProxyConn) close() {
	if !c.closed.CompareAndSwap(false, true) {
		return
	}
	close(c.done)
	_ = c.rw.Close()

	c.chanMu.Lock()
	chans := make([]*muxChannel, 0, len(c.chans))
	for _, ch := range c.chans {
		chans = append(chans, ch)
	}
	c.chanMu.Unlock()
	for _, ch := range chans {
		ch.teardown()
	}
	c.chanMu.Lock()
	c.chans = make(map[uint32]*muxChannel)
	c.chanMu.Unlock()

	c.fwdMu.Lock()
	forwards := make([]*muxRemoteForward, 0, len(c.forwards))
	for _, f := range c.forwards {
		forwards = append(forwards, f)
	}
	c.forwards = make(map[string]*muxRemoteForward)
	c.fwdMu.Unlock()
	for _, f := range forwards {
		_ = f.listener.Close()
	}

	if c.onClose != nil {
		c.onClose()
	}
}

func (c *muxProxyConn) send(msg any) error {
	if c.closed.Load() {
		return errMuxConnClosed
	}
	return c.writer.writeSshMessage(msg)
}

func (c *muxProxyConn) sendOpenFailure(peersID uint32, reason ssh.RejectionReason, message string) {
	_ = c.send(&sshChannelOpenFailureMsg{PeersID: peersID, Reason: reason, Message: message, Language: "en"})
}

// registerChannel allocates a local id and adds the channel to the table.
// It returns nil if the connection is already closed.
func (c *muxProxyConn) registerChannel(chanType string) *muxChannel {
	c.chanMu.Lock()
	defer c.chanMu.Unlock()
	if c.closed.Load() {
		return nil
	}
	ch := &muxChannel{
		conn:      c,
		localID:   c.nextID,
		chanType:  chanType,
		myWindow:  kMuxChannelWindowSize,
		inQueue:   newMuxByteQueue(),
		openReply: make(chan any, 1),
	}
	c.nextID++
	c.chans[ch.localID] = ch
	return ch
}

func (c *muxProxyConn) lookupChannel(id uint32) *muxChannel {
	c.chanMu.Lock()
	defer c.chanMu.Unlock()
	return c.chans[id]
}

func (c *muxProxyConn) removeChannel(id uint32) {
	c.chanMu.Lock()
	delete(c.chans, id)
	c.chanMu.Unlock()
}

func (c *muxProxyConn) handlePacket(pkt []byte) error {
	if len(pkt) == 0 {
		return fmt.Errorf("empty ssh packet")
	}
	switch pkt[0] {
	case kSshMsgGlobalRequest:
		var msg sshGlobalRequestMsg
		if err := ssh.Unmarshal(pkt, &msg); err != nil {
			return fmt.Errorf("parse global request failed: %v", err)
		}
		return c.handleGlobalRequest(&msg)
	case kSshMsgRequestSuccess, kSshMsgRequestFailure:
		// we never send global requests that want a reply
		return nil
	case kSshMsgChannelOpen:
		var msg sshChannelOpenMsg
		if err := ssh.Unmarshal(pkt, &msg); err != nil {
			return fmt.Errorf("parse channel open failed: %v", err)
		}
		c.handleChannelOpen(&msg)
		return nil
	case kSshMsgChannelOpenConfirm:
		var msg sshChannelOpenConfirmMsg
		if err := ssh.Unmarshal(pkt, &msg); err != nil {
			return fmt.Errorf("parse channel open confirmation failed: %v", err)
		}
		c.deliverOpenReply(msg.PeersID, &msg)
		return nil
	case kSshMsgChannelOpenFailure:
		var msg sshChannelOpenFailureMsg
		if err := ssh.Unmarshal(pkt, &msg); err != nil {
			return fmt.Errorf("parse channel open failure failed: %v", err)
		}
		c.deliverOpenReply(msg.PeersID, &msg)
		return nil
	case kSshMsgChannelWindowAdjust, kSshMsgChannelData, kSshMsgChannelExtendedData, kSshMsgChannelEOF,
		kSshMsgChannelClose, kSshMsgChannelRequest, kSshMsgChannelSuccess, kSshMsgChannelFailure:
		if len(pkt) < 5 {
			return fmt.Errorf("channel message %d too short", pkt[0])
		}
		id := binary.BigEndian.Uint32(pkt[1:5])
		ch := c.lookupChannel(id)
		if ch == nil {
			// the channel may have been torn down already
			debug("control master: ignore message %d for unknown channel %d", pkt[0], id)
			return nil
		}
		return ch.handlePacket(pkt)
	default:
		return fmt.Errorf("unexpected ssh message type %d", pkt[0])
	}
}

func (c *muxProxyConn) deliverOpenReply(id uint32, reply any) {
	ch := c.lookupChannel(id)
	if ch == nil {
		return
	}
	if confirm, ok := reply.(*sshChannelOpenConfirmMsg); ok && ch.remoteWin == nil {
		// bind in the read loop so later packets for this channel see a complete channel
		ch.remoteID = confirm.MyID
		ch.remoteWin = newMuxWindow(confirm.MyWindow)
		ch.remoteMax = min(confirm.MaxPacketSize, kMuxChannelMaxPacket)
	}
	select {
	case ch.openReply <- reply:
	default:
	}
}

func (c *muxProxyConn) replyGlobalRequest(msg *sshGlobalRequestMsg, ok bool) error {
	if !msg.WantReply {
		return nil
	}
	if ok {
		return c.send(&sshRequestSuccessMsg{})
	}
	return c.send(&sshRequestFailureMsg{})
}

func (c *muxProxyConn) handleGlobalRequest(msg *sshGlobalRequestMsg) error {
	switch msg.Type {
	case "keepalive@openssh.com", kMuxUdpModeRequest:
		return c.replyGlobalRequest(msg, true)
	case "tcpip-forward":
		var payload sshTcpipForwardPayload
		if err := ssh.Unmarshal(msg.Data, &payload); err != nil {
			return fmt.Errorf("parse tcpip-forward failed: %v", err)
		}
		port := strconv.Itoa(int(payload.Port))
		listenAddr := net.JoinHostPort(payload.Addr, port)
		if payload.Addr == "" || payload.Addr == "*" {
			listenAddr = ":" + port
		}
		ok, allocatedPort := c.addRemoteForward("tcp|"+net.JoinHostPort(payload.Addr, port), "forwarded-tcpip",
			"tcp", listenAddr, payload.Addr, payload.Port)
		if !ok {
			return c.replyGlobalRequest(msg, false)
		}
		if payload.Port == 0 {
			return c.send(&sshRequestSuccessMsg{Data: ssh.Marshal(struct{ Port uint32 }{allocatedPort})})
		}
		return c.replyGlobalRequest(msg, true)
	case "cancel-tcpip-forward":
		var payload sshTcpipForwardPayload
		if err := ssh.Unmarshal(msg.Data, &payload); err != nil {
			return fmt.Errorf("parse cancel-tcpip-forward failed: %v", err)
		}
		ok := c.cancelRemoteForward("tcp|" + net.JoinHostPort(payload.Addr, strconv.Itoa(int(payload.Port))))
		return c.replyGlobalRequest(msg, ok)
	case "streamlocal-forward@openssh.com":
		var payload sshStreamLocalForwardPayload
		if err := ssh.Unmarshal(msg.Data, &payload); err != nil {
			return fmt.Errorf("parse streamlocal-forward failed: %v", err)
		}
		ok, _ := c.addRemoteForward("unix|"+payload.SocketPath, "forwarded-streamlocal@openssh.com",
			"unix", payload.SocketPath, payload.SocketPath, 0)
		return c.replyGlobalRequest(msg, ok)
	case "cancel-streamlocal-forward@openssh.com":
		var payload sshStreamLocalForwardPayload
		if err := ssh.Unmarshal(msg.Data, &payload); err != nil {
			return fmt.Errorf("parse cancel-streamlocal-forward failed: %v", err)
		}
		ok := c.cancelRemoteForward("unix|" + payload.SocketPath)
		return c.replyGlobalRequest(msg, ok)
	default:
		debug("control master: reject unknown global request [%s]", msg.Type)
		return c.replyGlobalRequest(msg, false)
	}
}

func (c *muxProxyConn) addRemoteForward(key, chanType, network, listenAddr, addr string, port uint32) (bool, uint32) {
	if port != 0 {
		c.fwdMu.Lock()
		_, exists := c.forwards[key]
		c.fwdMu.Unlock()
		if exists {
			warning("control master: remote forwarding [%s] already exists", listenAddr)
			return false, 0
		}
	}
	listener, err := c.client.Listen(network, listenAddr)
	if err != nil {
		warning("control master: remote listen on [%s] failed: %v", listenAddr, err)
		return false, 0
	}
	allocatedPort := port
	if network == "tcp" && port == 0 {
		allocatedPort = listenerPort(listener)
		if allocatedPort == 0 {
			_ = listener.Close()
			warning("control master: remote listen on [%s] failed to allocate a port", listenAddr)
			return false, 0
		}
		key = "tcp|" + net.JoinHostPort(addr, strconv.Itoa(int(allocatedPort)))
	}
	f := &muxRemoteForward{key: key, chanType: chanType, addr: addr, port: allocatedPort, listener: listener}
	c.fwdMu.Lock()
	if c.closed.Load() {
		c.fwdMu.Unlock()
		_ = listener.Close()
		return false, 0
	}
	if _, exists := c.forwards[key]; exists {
		c.fwdMu.Unlock()
		_ = listener.Close()
		warning("control master: remote forwarding [%s] already exists", listenAddr)
		return false, 0
	}
	c.forwards[key] = f
	c.fwdMu.Unlock()
	go c.acceptLoop(f)
	debug("control master: remote forwarding [%s] started", listenAddr)
	return true, allocatedPort
}

func listenerPort(listener net.Listener) uint32 {
	if listener == nil {
		return 0
	}
	return addrPort(listener.Addr())
}

func addrPort(addr net.Addr) uint32 {
	if addr == nil {
		return 0
	}
	if tcpAddr, ok := addr.(*net.TCPAddr); ok && tcpAddr.Port > 0 {
		return uint32(tcpAddr.Port)
	}
	if host, portStr, err := net.SplitHostPort(addr.String()); err == nil {
		if port, err := strconv.Atoi(portStr); err == nil && port > 0 && net.ParseIP(host) != nil {
			return uint32(port)
		}
	}
	return 0
}

func (c *muxProxyConn) cancelRemoteForward(key string) bool {
	c.fwdMu.Lock()
	f, ok := c.forwards[key]
	if ok {
		delete(c.forwards, key)
	}
	c.fwdMu.Unlock()
	if !ok {
		return false
	}
	_ = f.listener.Close()
	return true
}

func (c *muxProxyConn) acceptLoop(f *muxRemoteForward) {
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			c.fwdMu.Lock()
			if c.forwards[f.key] == f {
				delete(c.forwards, f.key)
			}
			c.fwdMu.Unlock()
			return
		}
		go c.openForwardedChannel(f, conn)
	}
}

// originAddress extracts a valid ip and non-zero port for a forwarded-tcpip payload.
func originAddress(addr net.Addr) (string, uint32) {
	if addr != nil {
		if tcpAddr, ok := addr.(*net.TCPAddr); ok && tcpAddr.IP != nil && tcpAddr.Port > 0 {
			return tcpAddr.IP.String(), uint32(tcpAddr.Port)
		}
		if host, portStr, err := net.SplitHostPort(addr.String()); err == nil {
			if port, err := strconv.Atoi(portStr); err == nil && port > 0 && net.ParseIP(host) != nil {
				return host, uint32(port)
			}
		}
	}
	return "0.0.0.0", 1
}

// openForwardedChannel opens a server-initiated channel toward the peer for an accepted connection.
func (c *muxProxyConn) openForwardedChannel(f *muxRemoteForward, conn net.Conn) {
	ch := c.registerChannel(f.chanType)
	if ch == nil {
		_ = conn.Close()
		return
	}
	ch.stream = conn
	var payload []byte
	if f.chanType == "forwarded-tcpip" {
		originAddr, originPort := originAddress(conn.RemoteAddr())
		payload = ssh.Marshal(&sshForwardedTcpipPayload{
			Addr: f.addr, Port: f.port, OriginAddr: originAddr, OriginPort: originPort})
	} else {
		payload = ssh.Marshal(&sshForwardedStreamLocalPayload{SocketPath: f.addr})
	}
	err := c.send(&sshChannelOpenMsg{
		ChanType:         f.chanType,
		PeersID:          ch.localID,
		PeersWindow:      kMuxChannelWindowSize,
		MaxPacketSize:    kMuxChannelMaxPacket,
		TypeSpecificData: payload,
	})
	if err != nil {
		c.removeChannel(ch.localID)
		_ = conn.Close()
		return
	}

	var reply any
	select {
	case reply = <-ch.openReply:
	case <-time.After(kMuxOpenReplyTimeout):
	case <-c.done:
	}
	if _, ok := reply.(*sshChannelOpenConfirmMsg); !ok {
		if failure, isFailure := reply.(*sshChannelOpenFailureMsg); isFailure {
			debug("control master: forwarded channel rejected by mux client: %s", failure.Message)
		}
		c.removeChannel(ch.localID)
		_ = conn.Close()
		return
	}
	ch.startStreamPumps()
}

func (c *muxProxyConn) handleChannelOpen(msg *sshChannelOpenMsg) {
	if msg.MaxPacketSize < 9 {
		c.sendOpenFailure(msg.PeersID, ssh.ConnectionFailed, "invalid max packet size")
		return
	}
	switch msg.ChanType {
	case "session":
		go c.openSessionChannel(msg)
	case "direct-tcpip":
		var payload sshDirectTcpipPayload
		if err := ssh.Unmarshal(msg.TypeSpecificData, &payload); err != nil {
			c.sendOpenFailure(msg.PeersID, ssh.ConnectionFailed, "invalid direct-tcpip payload")
			return
		}
		go c.openDirectChannel(msg, "tcp", net.JoinHostPort(payload.RAddr, strconv.Itoa(int(payload.RPort))))
	case "direct-streamlocal@openssh.com":
		var payload sshDirectStreamLocalPayload
		if err := ssh.Unmarshal(msg.TypeSpecificData, &payload); err != nil {
			c.sendOpenFailure(msg.PeersID, ssh.ConnectionFailed, "invalid direct-streamlocal payload")
			return
		}
		go c.openDirectChannel(msg, "unix", payload.SocketPath)
	default:
		c.sendOpenFailure(msg.PeersID, ssh.UnknownChannelType, "unknown channel type: "+msg.ChanType)
	}
}

// bindChannel completes registration of a peer-initiated channel and confirms it.
func (c *muxProxyConn) bindChannel(ch *muxChannel, msg *sshChannelOpenMsg) error {
	ch.remoteID = msg.PeersID
	ch.remoteWin = newMuxWindow(msg.PeersWindow)
	ch.remoteMax = min(msg.MaxPacketSize, kMuxChannelMaxPacket)
	return c.send(&sshChannelOpenConfirmMsg{
		PeersID:       msg.PeersID,
		MyID:          ch.localID,
		MyWindow:      kMuxChannelWindowSize,
		MaxPacketSize: kMuxChannelMaxPacket,
	})
}

func (c *muxProxyConn) openSessionChannel(msg *sshChannelOpenMsg) {
	session, err := c.client.NewSession()
	if err != nil {
		c.sendOpenFailure(msg.PeersID, ssh.ConnectionFailed, fmt.Sprintf("new session failed: %v", err))
		return
	}
	stdinW, err := session.StdinPipe()
	if err != nil {
		_ = session.Close()
		c.sendOpenFailure(msg.PeersID, ssh.ConnectionFailed, fmt.Sprintf("stdin pipe failed: %v", err))
		return
	}
	stdoutR, err := session.StdoutPipe()
	if err != nil {
		_ = session.Close()
		c.sendOpenFailure(msg.PeersID, ssh.ConnectionFailed, fmt.Sprintf("stdout pipe failed: %v", err))
		return
	}
	ch := c.registerChannel(msg.ChanType)
	if ch == nil {
		_ = session.Close()
		return
	}
	ch.session, ch.stdinW, ch.stdoutR = session, stdinW, stdoutR
	if err := c.bindChannel(ch, msg); err != nil {
		ch.teardown()
	}
}

func (c *muxProxyConn) openDirectChannel(msg *sshChannelOpenMsg, network, addr string) {
	conn, err := c.client.DialTimeout(network, addr, c.dialTimeout)
	if err != nil {
		c.sendOpenFailure(msg.PeersID, ssh.ConnectionFailed, fmt.Sprintf("dial %s failed: %v", addr, err))
		return
	}
	ch := c.registerChannel(msg.ChanType)
	if ch == nil {
		_ = conn.Close()
		return
	}
	ch.stream = conn
	if err := c.bindChannel(ch, msg); err != nil {
		ch.teardown()
		return
	}
	ch.startStreamPumps()
}

func (ch *muxChannel) handlePacket(pkt []byte) error {
	switch pkt[0] {
	case kSshMsgChannelWindowAdjust:
		var msg sshWindowAdjustMsg
		if err := ssh.Unmarshal(pkt, &msg); err != nil {
			return fmt.Errorf("parse window adjust failed: %v", err)
		}
		if ch.remoteWin == nil {
			return fmt.Errorf("window adjust before channel open confirmation")
		}
		return ch.remoteWin.add(msg.AdditionalBytes)
	case kSshMsgChannelData:
		var msg sshChannelDataMsg
		if err := ssh.Unmarshal(pkt, &msg); err != nil {
			return fmt.Errorf("parse channel data failed: %v", err)
		}
		if uint64(msg.Length) > uint64(len(msg.Rest)) {
			return fmt.Errorf("channel data length %d exceeds packet", msg.Length)
		}
		return ch.handleData(msg.Rest[:msg.Length])
	case kSshMsgChannelExtendedData:
		var msg sshChannelExtendedDataMsg
		if err := ssh.Unmarshal(pkt, &msg); err != nil {
			return fmt.Errorf("parse channel extended data failed: %v", err)
		}
		if uint64(msg.Length) > uint64(len(msg.Rest)) {
			return fmt.Errorf("channel extended data length %d exceeds packet", msg.Length)
		}
		// clients do not send stderr to a server; consume the window and drop the data
		if err := ch.consumeWindow(msg.Length); err != nil {
			return err
		}
		return ch.replenishWindow(msg.Length)
	case kSshMsgChannelEOF:
		ch.gotEOF.Store(true)
		ch.inQueue.markEOF()
		if ch.stream != nil && ch.outDone.Load() {
			ch.teardown()
		}
		return nil
	case kSshMsgChannelClose:
		ch.teardown()
		// the peer either initiated the close or replied to ours; the channel id is retired now
		ch.conn.removeChannel(ch.localID)
		return nil
	case kSshMsgChannelRequest:
		var msg sshChannelRequestMsg
		if err := ssh.Unmarshal(pkt, &msg); err != nil {
			return fmt.Errorf("parse channel request failed: %v", err)
		}
		return ch.handleRequest(&msg)
	case kSshMsgChannelSuccess, kSshMsgChannelFailure:
		// we never send channel requests that want a reply
		return nil
	default:
		return fmt.Errorf("unexpected channel message type %d", pkt[0])
	}
}

func (ch *muxChannel) handleData(data []byte) error {
	if err := ch.consumeWindow(uint32(len(data))); err != nil {
		return err
	}
	if len(data) == 0 || ch.closed.Load() {
		return nil
	}
	buf := make([]byte, len(data))
	copy(buf, data)
	ch.inQueue.push(buf)
	return nil
}

// consumeWindow checks that inbound bytes fit into the window granted to the peer.
func (ch *muxChannel) consumeWindow(n uint32) error {
	ch.winMu.Lock()
	defer ch.winMu.Unlock()
	if n > ch.myWindow {
		return fmt.Errorf("channel data exceeds window: %d > %d", n, ch.myWindow)
	}
	ch.myWindow -= n
	return nil
}

// replenishWindow is called once the backend consumed inbound bytes; it tops up the
// peer's window when half of it has been used, which bounds the queued memory.
func (ch *muxChannel) replenishWindow(n uint32) error {
	ch.winMu.Lock()
	defer ch.winMu.Unlock()
	ch.consumed += n
	if ch.consumed < kMuxChannelWindowSize/2 {
		return nil
	}
	adjust := ch.consumed
	ch.consumed = 0
	ch.myWindow += adjust
	if ch.closed.Load() {
		return nil
	}
	return ch.conn.send(&sshWindowAdjustMsg{PeersID: ch.remoteID, AdditionalBytes: adjust})
}

func (ch *muxChannel) reply(msg *sshChannelRequestMsg, ok bool) error {
	if !msg.WantReply {
		return nil
	}
	if ok {
		return ch.conn.send(&sshChannelSuccessMsg{PeersID: ch.remoteID})
	}
	return ch.conn.send(&sshChannelFailureMsg{PeersID: ch.remoteID})
}

func (ch *muxChannel) handleRequest(msg *sshChannelRequestMsg) error {
	if ch.session == nil {
		debug("control master: reject request [%s] on non-session channel", msg.Request)
		return ch.reply(msg, false)
	}
	switch msg.Request {
	case "pty-req":
		var payload sshPtyRequestPayload
		if err := ssh.Unmarshal(msg.RequestSpecificData, &payload); err != nil {
			return fmt.Errorf("parse pty-req failed: %v", err)
		}
		if ch.started.Load() {
			return ch.reply(msg, false)
		}
		err := ch.session.RequestPty(payload.Term, int(payload.Rows), int(payload.Columns), parseTerminalModes(payload.Modelist))
		if err != nil {
			debug("control master: request pty failed: %v", err)
		}
		return ch.reply(msg, err == nil)
	case "env":
		var payload sshEnvPayload
		if err := ssh.Unmarshal(msg.RequestSpecificData, &payload); err != nil {
			return fmt.Errorf("parse env failed: %v", err)
		}
		err := ch.session.Setenv(payload.Name, payload.Value)
		return ch.reply(msg, err == nil)
	case "shell":
		return ch.reply(msg, ch.startSession(func() error { return ch.session.Shell() }))
	case "exec":
		var payload sshExecPayload
		if err := ssh.Unmarshal(msg.RequestSpecificData, &payload); err != nil {
			return fmt.Errorf("parse exec failed: %v", err)
		}
		return ch.reply(msg, ch.startSession(func() error { return ch.session.Start(payload.Command) }))
	case "subsystem":
		var payload sshSubsystemPayload
		if err := ssh.Unmarshal(msg.RequestSpecificData, &payload); err != nil {
			return fmt.Errorf("parse subsystem failed: %v", err)
		}
		return ch.reply(msg, ch.startSession(func() error { return ch.session.RequestSubsystem(payload.Subsystem) }))
	case "window-change":
		var payload sshWindowChangePayload
		if err := ssh.Unmarshal(msg.RequestSpecificData, &payload); err != nil {
			return fmt.Errorf("parse window-change failed: %v", err)
		}
		err := ch.session.WindowChange(int(payload.Rows), int(payload.Columns))
		return ch.reply(msg, err == nil)
	case "x11-req", "auth-agent-req@openssh.com":
		// the master can't route the resulting server-opened channels back to this client
		debug("control master: request [%s] is not supported via control socket", msg.Request)
		return ch.reply(msg, false)
	default:
		ok, err := ch.session.SendRequest(msg.Request, msg.WantReply, msg.RequestSpecificData)
		return ch.reply(msg, err == nil && ok)
	}
}

// startSession starts the remote shell, command or subsystem exactly once and wires the pumps.
func (ch *muxChannel) startSession(start func() error) bool {
	if !ch.started.CompareAndSwap(false, true) {
		return false
	}
	stderrR, err := ch.session.StderrPipe()
	if err != nil {
		debug("control master: stderr pipe failed: %v", err)
		return false
	}
	if err := start(); err != nil {
		if !errors.Is(err, io.EOF) {
			debug("control master: start session failed: %v", err)
			return false
		}
		debug("control master: start session reached EOF before reply, continuing")
	}
	ch.outWG.Add(2)
	go ch.pumpIn(ch.stdinW)
	go ch.pumpOut(ch.stdoutR, 0)
	go ch.pumpOut(stderrR, kSshExtendedDataStderr)
	go ch.waitSession()
	return true
}

func (ch *muxChannel) waitSession() {
	_ = ch.session.Wait()

	// the output pipes are normally at EOF once Wait returns; don't hang forever if not
	drained := make(chan struct{})
	go func() {
		ch.outWG.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(kMuxOutputDrainTimeout):
		debug("control master: session output drain timeout")
	}

	if !ch.closed.Load() {
		_ = ch.conn.send(&sshChannelRequestMsg{
			PeersID:             ch.remoteID,
			Request:             "exit-status",
			WantReply:           false,
			RequestSpecificData: ssh.Marshal(&sshExitStatusPayload{Status: uint32(ch.session.GetExitCode())}),
		})
	}
	ch.sendEOF()
	ch.teardown()
}

func (ch *muxChannel) startStreamPumps() {
	ch.outWG.Add(1)
	go ch.pumpIn(ch.stream)
	go func() {
		ch.pumpOut(ch.stream, 0)
		ch.outDone.Store(true)
		ch.sendEOF()
		if ch.gotEOF.Load() {
			ch.teardown()
		}
	}()
}

// pumpIn delivers queued inbound data to the backend writer and propagates EOF.
func (ch *muxChannel) pumpIn(w io.WriteCloser) {
	for {
		data, ok := ch.inQueue.pop()
		if !ok {
			break
		}
		if _, err := w.Write(data); err != nil {
			if !ch.closed.Load() {
				debug("control master: write to backend failed: %v", err)
			}
			ch.inQueue.abort()
			if ch.stream != nil {
				ch.teardown()
			}
			return
		}
		_ = ch.replenishWindow(uint32(len(data)))
	}
	if ch.closed.Load() {
		return
	}
	if ch.stream != nil {
		if cw, ok := w.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		return
	}
	ch.closeStdin()
}

// closeStdin signals EOF to the remote command's stdin exactly once.
func (ch *muxChannel) closeStdin() {
	ch.stdinOnce.Do(func() {
		if ch.stdinW != nil {
			_ = ch.stdinW.Close()
		}
	})
}

// pumpOut reads backend output and sends it to the peer within the peer's window.
func (ch *muxChannel) pumpOut(r io.Reader, ext uint32) {
	defer ch.outWG.Done()
	buf := make([]byte, ch.remoteMax)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if err := ch.writeData(ext, buf[:n]); err != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (ch *muxChannel) writeData(ext uint32, data []byte) error {
	for len(data) > 0 {
		if ch.closed.Load() {
			return errMuxConnClosed
		}
		n, err := ch.remoteWin.reserve(uint32(len(data)))
		if err != nil {
			return err
		}
		chunk := data[:n]
		data = data[n:]
		if ext == 0 {
			err = ch.conn.send(&sshChannelDataMsg{PeersID: ch.remoteID, Length: n, Rest: chunk})
		} else {
			err = ch.conn.send(&sshChannelExtendedDataMsg{PeersID: ch.remoteID, Datatype: ext, Length: n, Rest: chunk})
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (ch *muxChannel) sendEOF() {
	if ch.closed.Load() || !ch.sentEOF.CompareAndSwap(false, true) {
		return
	}
	_ = ch.conn.send(&sshChannelEOFMsg{PeersID: ch.remoteID})
}

func (ch *muxChannel) sendClose() {
	if !ch.sentClose.CompareAndSwap(false, true) {
		return
	}
	_ = ch.conn.send(&sshChannelCloseMsg{PeersID: ch.remoteID})
}

// teardown closes the channel: notifies the peer and releases the backend. The channel stays
// in the table until the peer's CLOSE arrives (or the connection closes), so late messages
// for it are recognized instead of being reported as unknown.
func (ch *muxChannel) teardown() {
	ch.closeOnce.Do(func() {
		if ch.remoteWin != nil {
			ch.sendClose()
		}
		ch.closed.Store(true)
		ch.inQueue.abort()
		if ch.remoteWin != nil {
			ch.remoteWin.close()
		}
		if ch.session != nil {
			ch.closeStdin()
			_ = ch.session.Close()
		}
		if ch.stream != nil {
			_ = ch.stream.Close()
		}
	})
}

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
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/trzsz/trzsz-go/trzsz"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// This file implements the master side of the OpenSSH multiplexing "passenger mode":
// the client hands its stdin, stdout and stderr file descriptors to the master over the
// control socket and the master runs the remote session on them. This is the mode used by
// the OpenSSH client (ssh -S, scp, rsync, ...) when a control socket is configured.

// muxNewSessionRequest is the body of MUX_C_NEW_SESSION.
type muxNewSessionRequest struct {
	wantTTY    bool
	wantX11    bool
	wantAgent  bool
	subsystem  bool
	escapeChar uint32
	term       string
	command    string
	envs       []string
}

func parseMuxNewSessionRequest(body []byte) (*muxNewSessionRequest, error) {
	req := &muxNewSessionRequest{}
	if _, ok := muxReadString(&body); !ok { // reserved
		return nil, fmt.Errorf("missing reserved field")
	}
	var flags [4]uint32
	for i := range flags {
		v, ok := muxReadUint32(&body)
		if !ok {
			return nil, fmt.Errorf("missing session flags")
		}
		flags[i] = v
	}
	req.wantTTY, req.wantX11, req.wantAgent, req.subsystem = flags[0] != 0, flags[1] != 0, flags[2] != 0, flags[3] != 0
	var ok bool
	if req.escapeChar, ok = muxReadUint32(&body); !ok {
		return nil, fmt.Errorf("missing escape char")
	}
	if req.term, ok = muxReadString(&body); !ok {
		return nil, fmt.Errorf("missing terminal type")
	}
	if req.command, ok = muxReadString(&body); !ok {
		return nil, fmt.Errorf("missing command")
	}
	for len(body) > 0 {
		env, ok := muxReadString(&body)
		if !ok {
			return nil, fmt.Errorf("invalid environment string")
		}
		req.envs = append(req.envs, env)
	}
	return req, nil
}

// muxPassenger is one passenger mode session: a remote session running on the
// file descriptors received from the client.
type muxPassenger struct {
	master  *muxMaster
	id      uint32
	conn    *net.UnixConn
	writer  *muxPacketWriter
	stdin   *os.File
	stdout  *os.File
	stderr  *os.File
	session SshSession
	tty     atomic.Bool

	// input is the passenger's stdin, filtered for the escape sequences on a terminal
	input io.Reader

	// the pipes must be created before the session starts
	stdinPipe  io.WriteCloser
	stdoutPipe io.Reader
	stderrPipe io.Reader

	// mu guards the terminal size and the trzsz filter, which the window change watcher reads
	mu          sync.Mutex
	width       int
	height      int
	trzszFilter *trzsz.TrzszFilter

	closed    atomic.Bool
	closeOnce sync.Once
	done      chan struct{}
}

// recvMuxFds receives one file descriptor per name from the client.
func recvMuxFds(conn *net.UnixConn, names ...string) ([]*os.File, error) {
	files := make([]*os.File, 0, len(names))
	for _, name := range names {
		file, err := muxRecvFd(conn, name)
		if err != nil {
			for _, f := range files {
				_ = f.Close()
			}
			return nil, err
		}
		files = append(files, file)
	}
	return files, nil
}

func (m *muxMaster) nextPassengerID() uint32 {
	return m.passengerSeq.Add(1)
}

// handleNewSession serves MUX_C_NEW_SESSION on conn until the session ends.
func (m *muxMaster) handleNewSession(conn *net.UnixConn, writer *muxPacketWriter, rid uint32, body []byte) {
	req, err := parseMuxNewSessionRequest(body)
	if err != nil {
		_ = writer.writeMuxMessage(kMuxSFailure, rid, fmt.Sprintf("invalid session request: %v", err))
		return
	}
	files, err := recvMuxFds(conn, "mux-stdin", "mux-stdout", "mux-stderr")
	if err != nil {
		_ = writer.writeMuxMessage(kMuxSFailure, rid, err.Error())
		return
	}
	_ = conn.SetDeadline(time.Time{})

	p := &muxPassenger{
		master: m,
		id:     m.nextPassengerID(),
		conn:   conn,
		writer: writer,
		stdin:  files[0],
		stdout: files[1],
		stderr: files[2],
		input:  files[0],
		done:   make(chan struct{}),
	}
	if err := p.open(req); err != nil {
		_ = writer.writeMuxMessage(kMuxSFailure, rid, err.Error())
		p.close()
		return
	}
	if err := writer.writeMuxMessage(kMuxSSessionOpened, rid, p.id); err != nil {
		p.close()
		return
	}
	m.addPassenger(p)
	defer m.removePassenger(p)

	if err := p.start(req); err != nil {
		debug("control master: passenger [%d] start failed: %v", p.id, err)
		p.close()
		return
	}
	p.run()
}

// open creates the remote session, applies the environment and requests a pty if wanted.
func (p *muxPassenger) open(req *muxNewSessionRequest) error {
	session, err := p.master.client.NewSession()
	if err != nil {
		return fmt.Errorf("new session failed: %v", err)
	}
	p.session = session
	if p.stdinPipe, err = session.StdinPipe(); err != nil {
		return fmt.Errorf("stdin pipe failed: %v", err)
	}
	if p.stdoutPipe, err = session.StdoutPipe(); err != nil {
		return fmt.Errorf("stdout pipe failed: %v", err)
	}
	if p.stderrPipe, err = session.StderrPipe(); err != nil {
		return fmt.Errorf("stderr pipe failed: %v", err)
	}

	// like the OpenSSH master, the agent and the display of the master serve the passengers
	if req.wantAgent {
		p.master.requestAgentForward(p.id, session)
	}
	if req.wantX11 {
		if err := requestX11Forward(p.master.param, p.master.client, session); err != nil {
			debug("control master: passenger [%d] %v", p.id, err)
		}
	}

	args := p.master.param.args
	rules, err := getSendEnvRules(args)
	if err != nil {
		return err
	}
	for _, env := range req.envs {
		name, value, _ := strings.Cut(env, "=")
		if !rules.permit(name) {
			debug("control master: passenger [%d] ignored env: %s", p.id, name)
			continue
		}
		if err := session.Setenv(name, value); err != nil {
			debug("control master: passenger [%d] set env [%s] failed: %v", p.id, name, err)
		}
	}
	setEnvs, err := getSetEnvs(args)
	if err != nil {
		return err
	}
	for _, env := range setEnvs {
		if err := session.Setenv(env.name, env.value); err != nil {
			debug("control master: passenger [%d] set env [%s] failed: %v", p.id, env.name, err)
		}
	}
	return nil
}

// start requests the pty and runs the shell, command or subsystem.
func (p *muxPassenger) start(req *muxNewSessionRequest) error {
	if req.wantTTY {
		if err := p.requestPty(req.term); err != nil {
			debug("control master: passenger [%d] request pty failed: %v", p.id, err)
			_ = p.writer.writeMuxMessage(kMuxSTtyAllocFail, p.id)
		} else {
			p.tty.Store(true)
			if req.escapeChar <= 0xff {
				p.input = &muxEscapeReader{reader: p.stdin, escapeChar: byte(req.escapeChar),
					stderr: p.stderr, terminate: p.close, afterNewline: true}
			}
		}
	}
	switch {
	case req.subsystem:
		return p.session.RequestSubsystem(req.command)
	case req.command != "":
		return p.session.Start(req.command)
	default:
		if err := p.session.Shell(); err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		return nil
	}
}

func (p *muxPassenger) requestPty(termType string) error {
	width, height, err := term.GetSize(int(p.stdin.Fd()))
	if err != nil {
		return fmt.Errorf("get terminal size failed: %v", err)
	}
	if termType == "" {
		termType = os.Getenv("TERM")
		if termType == "" {
			termType = "xterm-256color"
		}
	}
	if err := p.session.RequestPty(termType, height, width, ssh.TerminalModes{}); err != nil {
		return err
	}
	p.mu.Lock()
	p.width, p.height = width, height
	p.mu.Unlock()
	return nil
}

// checkWindowChange re-reads the passenger terminal size and notifies the remote on change.
func (p *muxPassenger) checkWindowChange() {
	if !p.tty.Load() || p.closed.Load() {
		return
	}
	width, height, err := term.GetSize(int(p.stdin.Fd()))
	if err != nil {
		return
	}
	p.mu.Lock()
	changed := width != p.width || height != p.height
	p.width, p.height = width, height
	trzszFilter := p.trzszFilter
	p.mu.Unlock()
	if changed {
		if trzszFilter != nil {
			trzszFilter.SetTerminalColumns(int32(width))
		}
		_ = p.session.WindowChange(height, width)
	}
}

// setupTrzsz runs the trzsz filter of the master's host configuration on the passenger's terminal.
func (p *muxPassenger) setupTrzsz() {
	if !p.tty.Load() {
		return
	}
	settings := getTrzszSettings(p.master.param.args)
	if !settings.enabled() || settings.relay {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.trzszFilter = settings.newFilter(p.master.param.args, p.master.client, p.session,
		p.input, p.stdout, p.stdinPipe, p.stdoutPipe, p.width)
}

// run pumps the session I/O and reports the exit status when the session ends.
func (p *muxPassenger) run() {
	// the client sends nothing more; its disconnect ends the session
	go func() {
		buf := make([]byte, 64)
		for {
			if _, err := p.conn.Read(buf); err != nil {
				break
			}
		}
		if !p.closed.Load() {
			debug("control master: passenger [%d] disconnected", p.id)
		}
		p.close()
	}()

	var outWG sync.WaitGroup
	p.setupTrzsz()
	p.mu.Lock()
	trzszFilter := p.trzszFilter
	p.mu.Unlock()
	if trzszFilter == nil { // the filter pumps stdin and stdout itself
		go func() {
			_, _ = io.Copy(p.stdinPipe, p.input)
			_ = p.stdinPipe.Close()
		}()
		outWG.Go(func() { _, _ = io.Copy(p.stdout, p.stdoutPipe) })
	}
	outWG.Go(func() { _, _ = io.Copy(p.stderr, p.stderrPipe) })

	// wait for the remote command, or for the passenger going away
	waited := make(chan struct{})
	go func() {
		_ = p.session.Wait()
		close(waited)
	}()
	select {
	case <-waited:
	case <-p.done:
		return
	}

	drained := make(chan struct{})
	go func() {
		outWG.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(kMuxOutputDrainTimeout):
		debug("control master: passenger [%d] output drain timeout", p.id)
	}

	if !p.closed.Load() {
		_ = p.writer.writeMuxMessage(kMuxSExitMessage, p.id, uint32(p.session.GetExitCode()))
	}
	p.close()
}

// close releases the session, the received files and the control connection.
func (p *muxPassenger) close() {
	p.closeOnce.Do(func() {
		p.closed.Store(true)
		close(p.done)
		p.mu.Lock()
		trzszFilter := p.trzszFilter
		p.mu.Unlock()
		if trzszFilter != nil {
			trzszFilter.ResetTerminal()
			trzszFilter.Close()
		}
		if p.session != nil {
			_ = p.session.Close()
		}
		for _, f := range []*os.File{p.stdin, p.stdout, p.stderr} {
			if f != nil {
				_ = f.Close()
			}
		}
		_ = p.conn.Close()
	})
}

// requestAgentForward forwards the agent of the master to the session of a passenger.
func (m *muxMaster) requestAgentForward(id uint32, session SshSession) {
	m.agentOnce.Do(func() {
		addr, err := getAgentAddr(m.param)
		if err != nil || addr == "" {
			debug("control master: no agent to forward: %v", err)
			return
		}
		if err := forwardToRemote(m.client, addr); err != nil && !errors.Is(err, errAgentAlreadyForwarded) {
			debug("control master: forward to agent [%s] failed: %v", addr, err)
			return
		}
		m.agentForwarded = true
	})
	if !m.agentForwarded {
		return
	}
	if ok, err := session.SendRequest(kAgentRequestName, true, nil); err != nil || !ok {
		debug("control master: passenger [%d] agent forwarding request failed: %v %v", id, ok, err)
	}
}

// muxEscapeReader handles the escape sequences of a passenger's terminal like OpenSSH: right
// after a newline, the escape char followed by '.' terminates the session, followed by '?'
// lists the sequences, and followed by itself sends the escape char once.
type muxEscapeReader struct {
	reader       io.Reader
	escapeChar   byte
	stderr       io.Writer
	terminate    func()
	afterNewline bool
	pending      bool // the escape char was typed right after a newline
	terminated   bool
	out          []byte
	err          error
}

func (r *muxEscapeReader) Read(p []byte) (int, error) {
	for len(r.out) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		n, err := r.reader.Read(p)
		r.out = r.filter(r.out[:0], p[:n])
		r.err = err
		if r.terminated {
			r.err = io.EOF
		}
	}
	n := copy(p, r.out)
	r.out = r.out[n:]
	return n, nil
}

func (r *muxEscapeReader) filter(out, in []byte) []byte {
	for _, b := range in {
		if r.pending {
			r.pending = false
			switch b {
			case '.':
				r.terminated = true
				_, _ = fmt.Fprintf(r.stderr, "%s.\r\n", r.escapeName())
				r.terminate()
				return out
			case '?':
				r.writeHelp()
				continue
			case r.escapeChar:
				out = append(out, b)
				r.afterNewline = false
				continue
			default:
				out = append(out, r.escapeChar)
			}
		}
		if r.afterNewline && b == r.escapeChar {
			r.pending = true
			continue
		}
		r.afterNewline = b == '\r' || b == '\n'
		out = append(out, b)
	}
	return out
}

func (r *muxEscapeReader) escapeName() string {
	if r.escapeChar < ' ' {
		return "^" + string(rune('A'-1+r.escapeChar))
	}
	return string(rune(r.escapeChar))
}

func (r *muxEscapeReader) writeHelp() {
	esc := r.escapeName()
	_, _ = fmt.Fprintf(r.stderr, "%s?\r\nSupported escape sequences:\r\n"+
		" %s.   - terminate session\r\n"+
		" %s?   - this message\r\n"+
		" %s%s   - send the escape character by typing it twice\r\n"+
		"(Note that escapes are only recognized immediately after newline.)\r\n", esc, esc, esc, esc, esc)
}

// notifyMuxPassengersConnLost shows the connection lost status on the terminal of every passenger
// of the masters using client, until the connection is back or the passenger is gone.
func notifyMuxPassengersConnLost(client *sshUdpClient) {
	muxMastersMu.Lock()
	masters := append([]*muxMaster(nil), muxMasters...)
	muxMastersMu.Unlock()
	for _, m := range masters {
		if m.client != SshClient(client) {
			continue
		}
		m.connMu.Lock()
		passengers := make([]*muxPassenger, 0, len(m.passengers))
		for _, p := range m.passengers {
			passengers = append(passengers, p)
		}
		m.connMu.Unlock()
		for _, p := range passengers {
			if p.tty.Load() {
				go writeConnLostStatus(p.stderr, client, func() bool { return !p.closed.Load() })
			}
		}
	}
}

// muxStdioForward is one stdio forwarding client (`ssh -W host:port`): the remote connection
// is pumped on the file descriptors received from the client.
type muxStdioForward struct {
	master    *muxMaster
	id        uint32
	conn      *net.UnixConn
	remote    net.Conn
	stdin     *os.File
	stdout    *os.File
	closeOnce sync.Once
}

// close unregisters the client and releases the remote connection, the received files and
// the control connection. A copy blocked on a received file ends with it (EOF or error).
func (f *muxStdioForward) close() {
	f.closeOnce.Do(func() {
		f.master.removeStdioForward(f)
		if f.remote != nil {
			_ = f.remote.Close()
		}
		_ = f.stdin.Close()
		_ = f.stdout.Close()
		_ = f.conn.Close()
	})
}

// handleStdioForward serves MUX_C_NEW_STDIO_FWD (`ssh -W host:port`) on conn.
func (m *muxMaster) handleStdioForward(conn *net.UnixConn, writer *muxPacketWriter, rid uint32, body []byte) {
	if _, ok := muxReadString(&body); !ok { // reserved
		_ = writer.writeMuxMessage(kMuxSFailure, rid, "invalid stdio forward request")
		return
	}
	host, ok := muxReadString(&body)
	if !ok {
		_ = writer.writeMuxMessage(kMuxSFailure, rid, "invalid stdio forward request")
		return
	}
	port, ok := muxReadUint32(&body)
	if !ok {
		_ = writer.writeMuxMessage(kMuxSFailure, rid, "invalid stdio forward request")
		return
	}
	files, err := recvMuxFds(conn, "mux-stdin", "mux-stdout")
	if err != nil {
		_ = writer.writeMuxMessage(kMuxSFailure, rid, err.Error())
		return
	}
	f := &muxStdioForward{master: m, id: m.nextPassengerID(), conn: conn, stdin: files[0], stdout: files[1]}
	defer f.close()
	_ = conn.SetDeadline(time.Time{})

	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	if f.remote, err = m.client.DialTimeout("tcp", addr, getConnectTimeout(m.param.args)); err != nil {
		_ = writer.writeMuxMessage(kMuxSFailure, rid, fmt.Sprintf("connect to %s failed: %v", addr, err))
		return
	}
	if err := writer.writeMuxMessage(kMuxSSessionOpened, rid, f.id); err != nil {
		return
	}
	m.addStdioForward(f)

	// the client sends nothing more; its disconnect ends the forwarding
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 64)
		for {
			if _, err := conn.Read(buf); err != nil {
				break
			}
		}
		f.close()
		close(done)
	}()

	var wg sync.WaitGroup
	wg.Go(func() {
		_, _ = io.Copy(f.remote, f.stdin)
		if cw, ok := f.remote.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	})
	wg.Go(func() {
		_, _ = io.Copy(f.stdout, f.remote)
		if cr, ok := f.remote.(interface{ CloseRead() error }); ok {
			_ = cr.CloseRead()
		}
	})
	wg.Wait()
	f.close()
	<-done
}

// muxForwardRequest is the body of MUX_C_OPEN_FWD and MUX_C_CLOSE_FWD.
type muxForwardRequest struct {
	ftype       uint32
	listenHost  string
	listenPort  uint32
	connectHost string
	connectPort uint32
}

func parseMuxForwardRequest(body []byte) (*muxForwardRequest, error) {
	req := &muxForwardRequest{}
	var ok bool
	if req.ftype, ok = muxReadUint32(&body); !ok {
		return nil, fmt.Errorf("missing forwarding type")
	}
	if req.listenHost, ok = muxReadString(&body); !ok {
		return nil, fmt.Errorf("missing listen host")
	}
	if req.listenPort, ok = muxReadUint32(&body); !ok {
		return nil, fmt.Errorf("missing listen port")
	}
	if req.connectHost, ok = muxReadString(&body); !ok {
		return nil, fmt.Errorf("missing connect host")
	}
	if req.connectPort, ok = muxReadUint32(&body); !ok {
		return nil, fmt.Errorf("missing connect port")
	}
	return req, nil
}

func (r *muxForwardRequest) key() string {
	return fmt.Sprintf("%d|%s|%d|%s|%d", r.ftype, r.listenHost, r.listenPort, r.connectHost, r.connectPort)
}

// bindCfg converts the listen side to tssh's bind config (nil address means the default bind).
func (r *muxForwardRequest) bindCfg() *bindCfg {
	b := &bindCfg{argument: fmt.Sprintf("%s:%d", r.listenHost, r.listenPort)}
	if r.listenPort == kMuxFwdUnixPort {
		b.argument = r.listenHost
		b.addr, b.port = &r.listenHost, -1
		return b
	}
	b.port = int(r.listenPort)
	if r.listenHost != "" {
		b.addr = &r.listenHost
	}
	return b
}

// forwardCfg converts the request to tssh's forward config.
func (r *muxForwardRequest) forwardCfg() *forwardCfg {
	b := r.bindCfg()
	f := &forwardCfg{bindAddr: b.addr, bindPort: b.port, destHost: r.connectHost, destPort: int(r.connectPort)}
	if r.connectPort == kMuxFwdUnixPort {
		f.destPort = -1
	}
	if f.destPort == -1 {
		f.argument = fmt.Sprintf("%s:%s", b.argument, r.connectHost)
	} else {
		f.argument = fmt.Sprintf("%s:%s:%d", b.argument, r.connectHost, f.destPort)
	}
	return f
}

// handleOpenForward serves MUX_C_OPEN_FWD: the forwarding lives until closed or the master exits.
func (m *muxMaster) handleOpenForward(writer *muxPacketWriter, rid uint32, body []byte) error {
	req, err := parseMuxForwardRequest(body)
	if err != nil {
		return writer.writeMuxMessage(kMuxSFailure, rid, fmt.Sprintf("invalid forwarding request: %v", err))
	}
	key := req.key()
	m.fwdMu.Lock()
	_, exists := m.forwards[key]
	m.fwdMu.Unlock()
	if exists {
		return writer.writeMuxMessage(kMuxSFailure, rid, "forwarding already exists")
	}

	args := m.param.args
	gateway, timeout := isGatewayPorts(args), getConnectTimeout(args)
	unlinkUnix := strings.EqualFold(getOptionConfig(args, "StreamLocalBindUnlink"), "yes")
	bindMask := streamLocalBindMask(args)

	var listeners []net.Listener
	switch req.ftype {
	case kMuxFwdLocal:
		listeners = localForwardTCP(m.client, req.forwardCfg(), gateway, timeout, unlinkUnix, bindMask)
	case kMuxFwdDynamic:
		listeners = dynamicForward(m.client, req.bindCfg(), gateway, timeout, unlinkUnix, bindMask)
	case kMuxFwdRemote:
		if req.listenPort == 0 {
			return writer.writeMuxMessage(kMuxSFailure, rid, "remote forwarding with dynamic port 0 is not supported via control socket")
		}
		listeners = remoteForwardTCP(m.client, req.forwardCfg(), gateway, timeout)
	default:
		return writer.writeMuxMessage(kMuxSFailure, rid, fmt.Sprintf("unknown forwarding type %d", req.ftype))
	}
	if len(listeners) == 0 {
		return writer.writeMuxMessage(kMuxSFailure, rid, "forwarding failed, see the control master output")
	}

	m.fwdMu.Lock()
	m.forwards[key] = listeners
	m.fwdMu.Unlock()
	debug("control master: forwarding [%s] opened by control command", key)
	return writer.writeMuxMessage(kMuxSOk, rid)
}

// handleCloseForward serves MUX_C_CLOSE_FWD.
func (m *muxMaster) handleCloseForward(writer *muxPacketWriter, rid uint32, body []byte) error {
	req, err := parseMuxForwardRequest(body)
	if err != nil {
		return writer.writeMuxMessage(kMuxSFailure, rid, fmt.Sprintf("invalid forwarding request: %v", err))
	}
	key := req.key()
	m.fwdMu.Lock()
	listeners, ok := m.forwards[key]
	delete(m.forwards, key)
	m.fwdMu.Unlock()
	if !ok {
		return writer.writeMuxMessage(kMuxSFailure, rid, "no such forwarding")
	}
	for _, listener := range listeners {
		_ = listener.Close()
	}
	debug("control master: forwarding [%s] closed by control command", key)
	return writer.writeMuxMessage(kMuxSOk, rid)
}

func (m *muxMaster) closeForwards() {
	m.fwdMu.Lock()
	forwards := m.forwards
	m.forwards = make(map[string][]net.Listener)
	m.fwdMu.Unlock()
	for _, listeners := range forwards {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}
}

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
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Client side of the mux passenger mode: the client passes its stdin, stdout and
// stderr to the master over the control socket and the master runs the session on them.

// muxClient is a connection to a control master speaking the mux protocol.
type muxClient struct {
	conn       *net.UnixConn
	tsshMaster bool // the master advertised the tssh hello extension
	nextRid    uint32
}

// dialMuxMaster connects to the control socket and performs the hello exchange.
func dialMuxMaster(socket string, timeout time.Duration) (*muxClient, error) {
	conn, err := net.DialTimeout("unix", socket, timeout)
	if err != nil {
		return nil, err
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("control socket is not a unix socket")
	}
	c := &muxClient{conn: unixConn}
	_ = conn.SetDeadline(time.Now().Add(kMuxHandshakeTimeout))
	if err := c.hello(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return c, nil
}

func (c *muxClient) close() {
	_ = c.conn.Close()
}

func (c *muxClient) rid() uint32 {
	c.nextRid++
	return c.nextRid
}

// hello exchanges the protocol version and records whether the master is a tssh master.
func (c *muxClient) hello() error {
	if err := muxWriteMessage(c.conn, kMuxMsgHello, kMuxProtocolVersion); err != nil {
		return fmt.Errorf("write mux hello failed: %v", err)
	}
	msgType, body, err := muxReadMessage(c.conn)
	if err != nil {
		return fmt.Errorf("read mux hello failed: %v", err)
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
	for len(body) > 0 {
		name, ok := muxReadString(&body)
		if !ok {
			break
		}
		if _, ok := muxReadString(&body); !ok {
			break
		}
		if name == kMuxHelloExtTssh {
			c.tsshMaster = true
		}
	}
	return nil
}

// request sends one mux request and returns the reply type and the body following the request id.
func (c *muxClient) request(msgType uint32, fields ...any) (uint32, []byte, error) {
	rid := c.rid()
	if err := muxWriteMessage(c.conn, msgType, append([]any{rid}, fields...)...); err != nil {
		return 0, nil, fmt.Errorf("write mux request failed: %v", err)
	}
	return c.readReply(rid)
}

// readReply reads the reply for rid and returns its type and the body following the request id.
func (c *muxClient) readReply(rid uint32) (uint32, []byte, error) {
	replyType, body, err := muxReadMessage(c.conn)
	if err != nil {
		return 0, nil, fmt.Errorf("read mux reply failed: %v", err)
	}
	gotRid, ok := muxReadUint32(&body)
	if !ok || gotRid != rid {
		return 0, nil, fmt.Errorf("unexpected request id in mux reply")
	}
	return replyType, body, nil
}

// muxReplyError turns a failure or permission denied reply into an error.
func muxReplyError(replyType uint32, body []byte) error {
	switch replyType {
	case kMuxSFailure, kMuxSPermissionDenied:
		reason, _ := muxReadString(&body)
		return errors.New(reason)
	default:
		return fmt.Errorf("unexpected mux reply 0x%08x", replyType)
	}
}

// aliveCheck returns the pid of the master process.
func (c *muxClient) aliveCheck() (uint32, error) {
	replyType, body, err := c.request(kMuxCAliveCheck)
	if err != nil {
		return 0, err
	}
	if replyType != kMuxSAlive {
		return 0, muxReplyError(replyType, body)
	}
	pid, _ := muxReadUint32(&body)
	return pid, nil
}

// openForward asks the master to open a forwarding (MUX_C_OPEN_FWD). For a remote
// forwarding with port 0 it returns the port allocated by the server.
func (c *muxClient) openForward(req *muxForwardRequest) (uint32, error) {
	replyType, body, err := c.request(kMuxCOpenFwd,
		req.ftype, req.listenHost, req.listenPort, req.connectHost, req.connectPort)
	if err != nil {
		return 0, err
	}
	switch replyType {
	case kMuxSOk:
		return req.listenPort, nil
	case kMuxSRemotePort:
		port, _ := muxReadUint32(&body)
		return port, nil
	default:
		return 0, muxReplyError(replyType, body)
	}
}

// closeForward asks the master to close a forwarding (MUX_C_CLOSE_FWD).
func (c *muxClient) closeForward(req *muxForwardRequest) error {
	replyType, body, err := c.request(kMuxCCloseFwd,
		req.ftype, req.listenHost, req.listenPort, req.connectHost, req.connectPort)
	if err != nil {
		return err
	}
	if replyType != kMuxSOk {
		return muxReplyError(replyType, body)
	}
	return nil
}

// muxBool converts a flag to its mux wire representation.
func muxBool(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

// newSession asks the master to run a session on the given files and returns the session id.
func (c *muxClient) newSession(req *muxNewSessionRequest, stdin, stdout, stderr *os.File) (uint32, error) {
	rid := c.rid()
	fields := []any{rid, "", muxBool(req.wantTTY), muxBool(req.wantX11), muxBool(req.wantAgent), muxBool(req.subsystem),
		req.escapeChar, req.term, req.command}
	for _, env := range req.envs {
		fields = append(fields, env)
	}
	if err := muxWriteMessage(c.conn, kMuxCNewSession, fields...); err != nil {
		return 0, fmt.Errorf("write session request failed: %v", err)
	}
	for _, f := range []*os.File{stdin, stdout, stderr} {
		if err := muxSendFd(c.conn, int(f.Fd())); err != nil {
			return 0, err
		}
	}
	return c.readSessionOpened(rid)
}

// stdioForward asks the master to connect host:port and pump it to the given files (`ssh -W`).
func (c *muxClient) stdioForward(host string, port uint32, stdin, stdout *os.File) (uint32, error) {
	rid := c.rid()
	if err := muxWriteMessage(c.conn, kMuxCNewStdioFwd, rid, "", host, port); err != nil {
		return 0, fmt.Errorf("write stdio forward request failed: %v", err)
	}
	for _, f := range []*os.File{stdin, stdout} {
		if err := muxSendFd(c.conn, int(f.Fd())); err != nil {
			return 0, err
		}
	}
	return c.readSessionOpened(rid)
}

// readSessionOpened reads the reply to a session request and returns the session id.
func (c *muxClient) readSessionOpened(rid uint32) (uint32, error) {
	replyType, body, err := c.readReply(rid)
	if err != nil {
		return 0, err
	}
	if replyType != kMuxSSessionOpened {
		return 0, muxReplyError(replyType, body)
	}
	sessionID, _ := muxReadUint32(&body)
	return sessionID, nil
}

// waitExit waits for the session to end and returns its exit status. onTtyFail is called
// if the master could not allocate a pty. A connection closed without an exit message
// yields 255, like OpenSSH.
func (c *muxClient) waitExit(sessionID uint32, onTtyFail func()) int {
	for {
		msgType, body, err := muxReadMessage(c.conn)
		if err != nil {
			return 255
		}
		id, ok := muxReadUint32(&body)
		if !ok || id != sessionID {
			continue
		}
		switch msgType {
		case kMuxSTtyAllocFail:
			if onTtyFail != nil {
				onTtyFail()
			}
		case kMuxSExitMessage:
			code, _ := muxReadUint32(&body)
			return int(code)
		}
	}
}

// muxForwardRequestFromCfg converts tssh forwarding configs to the mux wire representation.
func muxForwardRequestFromCfg(ftype uint32, bind *bindCfg, f *forwardCfg) *muxForwardRequest {
	req := &muxForwardRequest{ftype: ftype}
	if bind.addr != nil {
		req.listenHost = *bind.addr
	}
	if bind.port == -1 {
		req.listenPort = kMuxFwdUnixPort
	} else {
		req.listenPort = uint32(bind.port)
	}
	if f != nil {
		req.connectHost = f.destHost
		if f.destPort == -1 {
			req.connectPort = kMuxFwdUnixPort
		} else {
			req.connectPort = uint32(f.destPort)
		}
	}
	return req
}

// muxForwardRequestFromForward converts a local or remote forwarding config to the mux wire representation.
func muxForwardRequestFromForward(ftype uint32, f *forwardCfg) *muxForwardRequest {
	return muxForwardRequestFromCfg(ftype, &bindCfg{addr: f.bindAddr, port: f.bindPort}, f)
}

// muxForwardRequests converts the -D / -L / -R forwardings of the command line, and of the config
// unless cmdLineOnly is set, to mux forwarding requests (see collectForwardCfgs).
func muxForwardRequests(param *sshParam, cmdLineOnly bool) []*muxForwardRequest {
	dynamic, local, remote := collectForwardCfgs(param, cmdLineOnly)
	var requests []*muxForwardRequest
	for _, b := range dynamic {
		requests = append(requests, muxForwardRequestFromCfg(kMuxFwdDynamic, b, nil))
	}
	for _, f := range local {
		requests = append(requests, muxForwardRequestFromForward(kMuxFwdLocal, f))
	}
	for _, f := range remote {
		requests = append(requests, muxForwardRequestFromForward(kMuxFwdRemote, f))
	}
	return requests
}

// muxForwardCommand implements `tssh -O forward` and `tssh -O cancel`: it opens or closes the
// -L / -R / -D forwardings given on the command line in the running master.
func muxForwardCommand(socket string, param *sshParam, cancel bool) int {
	requests := muxForwardRequests(param, true)
	if len(requests) == 0 {
		fmt.Fprintf(os.Stderr, "No forwarding specified, use -L, -R or -D\r\n")
		return kExitCodeToolsError
	}

	client, err := dialMuxMaster(socket, time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Control socket connect(%s): %v\r\n", socket, err)
		return kExitCodeToolsError
	}
	defer client.close()

	code := 0
	for _, req := range requests {
		if cancel {
			err = client.closeForward(req)
		} else {
			var port uint32
			port, err = client.openForward(req)
			if err == nil && req.ftype == kMuxFwdRemote && req.listenPort == 0 {
				fmt.Fprintf(os.Stderr, "Allocated port %d for remote forward\r\n", port)
			}
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Control request failed: %v\r\n", err)
			code = kExitCodeToolsError
		}
	}
	return code
}

// muxPassengerEligible reports whether this login can run as a passenger of a tssh master.
// Logins that need their own ssh channels or the session output in this process use proxy mode.
func muxPassengerEligible(args *sshArgs) bool {
	if getExpectCount(args, "") > 0 {
		return false
	}
	if isX11ForwardEnabled(args) {
		return false
	}
	if isAgentForwardEnabled(args) {
		return false
	}
	if len(args.UploadFile.values) > 0 || args.Attach || strings.EqualFold(getExOptionConfig(args, "UdpSessionAttach"), "yes") {
		return false
	}
	if strings.EqualFold(getExOptionConfig(args, "EnableWaypipe"), "yes") || isRunningTmuxIntegration() {
		return false
	}
	for _, f := range args.LocalForward.cfgs {
		if f.udp {
			return false
		}
	}
	for _, f := range args.RemoteForward.cfgs {
		if f.udp {
			return false
		}
	}
	if len(getAllExOptionConfig(args, "UdpLocalForward", true)) > 0 || len(getAllExOptionConfig(args, "UdpRemoteForward", true)) > 0 {
		return false
	}
	return true
}

// muxOpenSSHPassengerEligible reports whether this login can hand its terminal to an OpenSSH master.
// UDP mode needs proxy mode to start tsshd, which OpenSSH knows nothing about. With trzsz enabled
// it needs proxy mode too: an OpenSSH master runs the session on the terminal itself, so tssh
// could not filter it.
func muxOpenSSHPassengerEligible(param *sshParam) bool {
	if param.udpMode != kUdpModeNo {
		return false
	}
	return !getTrzszSettings(param.args).enabled()
}

// muxPassengerEscapeChar returns the escape char the master handles on the terminal, or none.
func muxPassengerEscapeChar(args *sshArgs) uint32 {
	escapeChar, escapeTime := getEscapeConfig(args)
	if escapeTime <= 0 {
		return kMuxEscapeCharNone
	}
	return uint32(escapeChar)
}

// muxPassengerForwards sends the -L / -R / -D forwardings of the command line and the config to the master.
func muxPassengerForwards(mc *muxClient, param *sshParam) {
	args := param.args
	if strings.EqualFold(getOptionConfig(args, "ClearAllForwardings"), "yes") {
		return
	}
	for _, req := range muxForwardRequests(param, false) {
		if _, err := mc.openForward(req); err != nil {
			warning("forwarding [%s:%d -> %s:%d] failed: %v", req.listenHost, req.listenPort, req.connectHost, req.connectPort, err)
		}
	}
}

// passengerEnvs returns the SendEnv and SetEnv variables as NAME=VALUE strings for the master.
func passengerEnvs(args *sshArgs) ([]string, string, error) {
	sendEnvs, err := getSendEnvs(args)
	if err != nil {
		return nil, "", err
	}
	setEnvs, err := getSetEnvs(args)
	if err != nil {
		return nil, "", err
	}
	var envs []string
	term := ""
	for _, env := range append(sendEnvs, setEnvs...) {
		envs = append(envs, env.name+"="+env.value)
	}
	for _, env := range setEnvs {
		if env.name == "TERM" {
			term = env.value
		}
	}
	if term == "" {
		term = os.Getenv("TERM")
		if term == "" {
			term = "xterm-256color"
		}
	}
	return envs, term, nil
}

// waitMuxMasterClosed blocks until the master closes the control connection or a termination signal arrives.
func waitMuxMasterClosed(mc *muxClient) {
	closed := make(chan struct{})
	go func() {
		buf := make([]byte, 64)
		for {
			if _, err := mc.conn.Read(buf); err != nil {
				break
			}
		}
		close(closed)
	}()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)
	select {
	case <-closed:
	case <-sigCh:
	}
}

// runAsMuxPassenger attaches to a running control master as a passenger: the master runs the
// session on this process's terminal. Returns false if there is no usable master or the login
// needs proxy mode (see muxPassengerEligible and muxOpenSSHPassengerEligible).
func runAsMuxPassenger(param *sshParam) (int, bool) {
	args := param.args
	ctrlPath := resolveControlPath(param)
	if ctrlPath == "" {
		return 0, false
	}
	if master, _ := getControlMasterMode(args); master && !param.muxPersisted {
		return 0, false
	}
	if !muxPassengerEligible(args) {
		debug("control master: features require proxy mode, not attaching as passenger")
		return 0, false
	}

	socket, err := resolveControlSocket(param, ctrlPath)
	if err != nil {
		return 0, false
	}
	if !isFileExist(socket) {
		return 0, false
	}

	mc, err := dialMuxMaster(socket, time.Second)
	if err != nil {
		debug("control master: dial [%s] failed: %v", socket, err)
		return 0, false
	}
	if !mc.tsshMaster && !muxOpenSSHPassengerEligible(param) {
		debug("control master: [%s] is an OpenSSH master, using proxy mode", socket)
		mc.close()
		return 0, false
	}
	pid, err := mc.aliveCheck()
	if err != nil {
		mc.close()
		warning("control master alive check failed: %v", err)
		return 0, false
	}
	defer mc.close()
	debug("login to [%s] as passenger of the control master [%s] (pid %d)", args.Destination, socket, pid)

	cmd, tty, err := parseCmdAndTTY(param)
	if err != nil {
		warning("%v", err)
		return kExitCodeOpenSession, true
	}
	execLocalCommand(param)
	if !param.muxPersisted { // the background master has set up the forwardings already
		muxPassengerForwards(mc, param)
	}

	if args.StdioForward != "" {
		host, portStr, err := net.SplitHostPort(args.StdioForward)
		if err != nil {
			warning("invalid stdio forwarding address [%s]: %v", args.StdioForward, err)
			return kExitCodeIoFwFailed, true
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			warning("invalid stdio forwarding port [%s]: %v", portStr, err)
			return kExitCodeIoFwFailed, true
		}
		if _, err := mc.stdioForward(host, uint32(port), os.Stdin, os.Stdout); err != nil {
			warning("stdio forwarding [%s] failed: %v", args.StdioForward, err)
			return kExitCodeIoFwFailed, true
		}
		waitMuxMasterClosed(mc)
		return 0, true
	}

	if args.NoCommand {
		waitMuxMasterClosed(mc)
		return 0, true
	}

	envs, term, err := passengerEnvs(args)
	if err != nil {
		warning("%v", err)
		return kExitCodeOpenSession, true
	}
	escapeChar := kMuxEscapeCharNone
	if tty && isTerminal {
		escapeChar = muxPassengerEscapeChar(args)
	}
	req := &muxNewSessionRequest{
		wantTTY:    tty,
		subsystem:  args.Subsystem,
		escapeChar: escapeChar,
		term:       term,
		command:    cmd,
		envs:       envs,
	}
	sessionID, err := mc.newSession(req, os.Stdin, os.Stdout, os.Stderr)
	if err != nil {
		warning("open session via control master failed: %v", err)
		return kExitCodeOpenSession, true
	}

	var rawState *stdinState
	if tty && isTerminal {
		if rawState, err = makeStdinRaw(); err != nil {
			warning("%v", err)
		}
		defer resetStdin(rawState)
	}

	// the master owns the terminal now: relay window changes to it, exit on termination signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGWINCH, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)
	go func() {
		for sig := range sigCh {
			if sig == syscall.SIGWINCH {
				_ = syscall.Kill(int(pid), syscall.SIGWINCH)
				continue
			}
			mc.close()
			return
		}
	}()

	code := mc.waitExit(sessionID, func() {
		if rawState != nil {
			resetStdin(rawState)
		}
	})
	return code, true
}

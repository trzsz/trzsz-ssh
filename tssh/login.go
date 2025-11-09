/*
MIT License

Copyright (c) 2023-2025 The Trzsz SSH Authors.

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
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/alessio/shellescape"
	"github.com/trzsz/ssh_config"
	"golang.org/x/crypto/ssh"
)

var kDefaultConnectTimeout = 10 * time.Second

type proxyJump struct {
	client SshClient
	name   string
}

type sshParam struct {
	host    string
	port    string
	user    string
	addr    string
	proxies []string
	command string
	control bool
	proxy   *proxyJump
}

func joinHostPort(host, port string) string {
	if !strings.HasPrefix(host, "[") && strings.ContainsRune(host, ':') {
		return fmt.Sprintf("[%s]:%s", host, port)
	}
	return fmt.Sprintf("%s:%s", host, port)
}

func parseDestination(dest string) (user, host, port string) {
	// user
	idx := strings.Index(dest, "@")
	if idx >= 0 {
		user = dest[:idx]
		dest = dest[idx+1:]
	}

	// port
	idx = strings.Index(dest, "]:")
	if idx > 0 && dest[0] == '[' { // ipv6 port
		port = dest[idx+2:]
		dest = dest[1:idx]
	} else {
		tokens := strings.Split(dest, ":")
		if len(tokens) == 2 { // ipv4 port
			port = tokens[1]
			dest = tokens[0]
		}
	}

	host = dest
	return
}

func getSshParam(args *sshArgs) (*sshParam, error) {
	param := &sshParam{}

	// login dest
	destUser, destHost, destPort := parseDestination(args.Destination)
	args.Destination = destHost

	// login host
	param.host = destHost
	if hostName := getConfig(destHost, "HostName"); hostName != "" {
		var err error
		param.host, err = expandTokens(hostName, args, param, "%h")
		if err != nil {
			return nil, err
		}
	}

	// login user
	if args.LoginName != "" {
		param.user = args.LoginName
	} else if destUser != "" {
		param.user = destUser
	} else {
		userName := getConfig(destHost, "User")
		if userName != "" {
			param.user = userName
		} else {
			currentUser, err := user.Current()
			if err != nil {
				return nil, fmt.Errorf("get current user failed: %v", err)
			}
			userName = currentUser.Username
			if idx := strings.LastIndexByte(userName, '\\'); idx >= 0 {
				userName = userName[idx+1:]
			}
			param.user = userName
		}
	}

	// login port
	if args.Port > 0 {
		param.port = strconv.Itoa(args.Port)
	} else if destPort != "" {
		param.port = destPort
	} else {
		port := getConfig(destHost, "Port")
		if port != "" {
			param.port = port
		} else {
			param.port = "22"
		}
	}

	// dns srv
	if dnsSrvName := getExOptionConfig(args, "DnsSrvName"); dnsSrvName != "" {
		host, port, err := lookupDnsSrv(dnsSrvName)
		if err != nil {
			warning("lookup dns srv [%s] failed: %v", dnsSrvName, err)
		} else {
			debug("dns srv [%s] resolves to [%s:%s]", dnsSrvName, host, port)
			param.host = host
			param.port = port
		}
	}

	// login addr
	param.addr = joinHostPort(param.host, param.port)

	// login proxy
	getProxyParam(args, param)

	// expand proxy
	var err error
	if param.command != "" {
		param.command, err = expandTokens(param.command, args, param, "%hnpr")
		if err != nil {
			return nil, fmt.Errorf("expand ProxyCommand [%s] failed: %v", param.command, err)
		}
	}
	for i := 0; i < len(param.proxies); i++ {
		param.proxies[i], err = expandTokens(strings.TrimSpace(param.proxies[i]), args, param, "%hnpr")
		if err != nil {
			return nil, fmt.Errorf("expand ProxyJump [%s] failed: %v", param.proxies[i], err)
		}
	}

	return param, nil
}

func getProxyParam(args *sshArgs, param *sshParam) {
	proxyJump := args.ProxyJump // -J
	if proxyJump == "" {
		proxyJump = args.Option.get("ProxyJump")
	}
	if strings.ToLower(proxyJump) == "none" {
		return
	}
	if proxyJump != "" {
		param.proxies = strings.Split(proxyJump, ",")
		return
	}

	proxyCommand := args.Option.get("ProxyCommand")
	if strings.ToLower(proxyCommand) == "none" {
		return
	}
	if proxyCommand != "" {
		param.command = proxyCommand
		return
	}

	proxyJump = getConfig(args.Destination, "ProxyJump")
	if proxyJump != "" {
		param.proxies = strings.Split(proxyJump, ",")
		return
	}

	proxyCommand = getConfig(args.Destination, "ProxyCommand")
	if proxyCommand != "" {
		param.command = proxyCommand
		return
	}
}

type cmdAddr struct {
	addr string
}

func (*cmdAddr) Network() string {
	return "cmd"
}

func (a *cmdAddr) String() string {
	return a.addr
}

type cmdPipe struct {
	stdin  io.WriteCloser
	stdout io.ReadCloser
	addr   string
}

func (p *cmdPipe) LocalAddr() net.Addr {
	return &cmdAddr{"127.0.0.1:22"}
}

func (p *cmdPipe) RemoteAddr() net.Addr {
	return &cmdAddr{p.addr}
}

func (p *cmdPipe) Read(b []byte) (int, error) {
	return p.stdout.Read(b)
}

func (p *cmdPipe) Write(b []byte) (int, error) {
	return p.stdin.Write(b)
}

func (p *cmdPipe) SetDeadline(t time.Time) error {
	return nil
}

func (p *cmdPipe) SetReadDeadline(t time.Time) error {
	return nil
}

func (p *cmdPipe) SetWriteDeadline(t time.Time) error {
	return nil
}

func (p *cmdPipe) Close() error {
	err := p.stdin.Close()
	err2 := p.stdout.Close()
	if err != nil {
		return err
	}
	return err2
}

func execProxyCommand(args *sshArgs, param *sshParam) (net.Conn, string, error) {
	command, err := expandTokens(param.command, args, param, "%hnpr")
	if err != nil {
		return nil, param.command, err
	}
	command = resolveHomeDir(command)
	debug("exec proxy command: %s", command)

	argv, err := splitCommandLine(command)
	if err != nil || len(argv) == 0 {
		return nil, command, fmt.Errorf("split proxy command failed: %v", err)
	}
	if enableDebugLogging {
		for i, arg := range argv {
			debug("proxy command argv[%d] = %s", i, arg)
		}
	}
	cmd := exec.Command(argv[0], argv[1:]...)

	cmdIn, err := cmd.StdinPipe()
	if err != nil {
		return nil, command, err
	}
	cmdOut, err := cmd.StdoutPipe()
	if err != nil {
		return nil, command, err
	}
	if err := cmd.Start(); err != nil {
		return nil, command, err
	}

	return &cmdPipe{stdin: cmdIn, stdout: cmdOut, addr: param.addr}, command, nil
}

func execLocalCommand(args *sshArgs, param *sshParam) {
	if strings.ToLower(getOptionConfig(args, "PermitLocalCommand")) != "yes" {
		return
	}
	localCmd := getOptionConfig(args, "LocalCommand")
	if localCmd == "" {
		return
	}
	expandedCmd, err := expandTokens(localCmd, args, param, "%CdfHhIijKkLlnprTtu")
	if err != nil {
		warning("expand LocalCommand [%s] failed: %v", localCmd, err)
		return
	}
	resolvedCmd := resolveHomeDir(expandedCmd)
	debug("exec local command: %s", resolvedCmd)

	argv, err := splitCommandLine(resolvedCmd)
	if err != nil || len(argv) == 0 {
		warning("split local command [%s] failed: %v", resolvedCmd, err)
		return
	}
	if enableDebugLogging {
		for i, arg := range argv {
			debug("local command argv[%d] = %s", i, arg)
		}
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		warning("exec local command [%s] failed: %v", resolvedCmd, err)
	}
}

func parseRemoteCommand(args *sshArgs, param *sshParam) (string, error) {
	command := args.Option.get("RemoteCommand")
	if args.Command != "" && command != "" && strings.ToLower(command) != "none" {
		return "", fmt.Errorf("cannot execute command-line and remote command")
	}
	if args.Command != "" {
		if len(args.Argument) == 0 {
			return args.Command, nil
		}
		return shellescape.QuoteCommand(append([]string{args.Command}, args.Argument...)), nil
	}
	if strings.ToLower(command) == "none" {
		return "", nil
	}
	if command == "" {
		command = getConfig(args.Destination, "RemoteCommand")
	}
	expandedCmd, err := expandTokens(command, args, param, "%CdhijkLlnpru")
	if err != nil {
		return "", fmt.Errorf("expand RemoteCommand [%s] failed: %v", command, err)
	}
	return expandedCmd, nil
}

func parseCmdAndTTY(args *sshArgs, param *sshParam) (cmd string, tty bool, err error) {
	cmd, err = parseRemoteCommand(args, param)
	if err != nil {
		return
	}

	if args.DisableTTY && args.ForceTTY {
		err = fmt.Errorf("cannot specify -t with -T")
		return
	}
	if args.DisableTTY {
		tty = false
		return
	}
	if args.ForceTTY {
		tty = true
		return
	}

	requestTTY := getConfig(args.Destination, "RequestTTY")
	switch strings.ToLower(requestTTY) {
	case "", "auto":
		tty = isTerminal && (cmd == "")
	case "no":
		tty = false
	case "force":
		tty = true
	case "yes":
		tty = isTerminal
	default:
		err = fmt.Errorf("unknown RequestTTY option: %s", requestTTY)
	}
	return
}

var lastServerAliveTime atomic.Pointer[time.Time]

type connWithTimeout struct {
	net.Conn
	timeout   time.Duration
	firstRead bool
}

func (c *connWithTimeout) Read(b []byte) (n int, err error) {
	if !c.firstRead {
		n, err = c.Conn.Read(b)
		if err == nil {
			now := time.Now()
			lastServerAliveTime.Store(&now)
		}
		return
	}
	if c.timeout > 0 {
		n, err = doWithTimeout(func() (int, error) {
			return c.Conn.Read(b)
		}, c.timeout)
	} else {
		n, err = c.Conn.Read(b)
	}
	c.firstRead = false
	return
}

func setupLogLevel(args *sshArgs) func() {
	previousDebug := enableDebugLogging
	previousWarning := envbleWarningLogging
	reset := func() {
		enableDebugLogging = previousDebug
		envbleWarningLogging = previousWarning
	}
	if args.Debug {
		enableDebugLogging = true
		envbleWarningLogging = true
		return reset
	}
	switch strings.ToLower(getOptionConfig(args, "LogLevel")) {
	case "quiet", "fatal", "error":
		enableDebugLogging = false
		envbleWarningLogging = false
	case "debug", "debug1", "debug2", "debug3":
		enableDebugLogging = true
		envbleWarningLogging = true
	case "info", "verbose":
		enableDebugLogging = false
		envbleWarningLogging = true
	}
	return reset
}

func getNetworkAddressFamily(args *sshArgs) string {
	if args.IPv4Only {
		if args.IPv6Only {
			return "tcp"
		}
		return "tcp4"
	}
	if args.IPv6Only {
		return "tcp6"
	}
	switch strings.ToLower(getOptionConfig(args, "AddressFamily")) {
	case "inet":
		return "tcp4"
	case "inet6":
		return "tcp6"
	default:
		return "tcp"
	}
}

func getConnectTimeout(args *sshArgs) time.Duration {
	connectTimeout := getOptionConfig(args, "ConnectTimeout")
	if connectTimeout == "" {
		return kDefaultConnectTimeout
	}
	value, err := strconv.Atoi(connectTimeout)
	if err != nil {
		warning("ConnectTimeout [%s] invalid: %v", connectTimeout, err)
		return kDefaultConnectTimeout
	}
	if value <= 0 {
		return 24 * time.Hour
	}
	return time.Duration(value) * time.Second
}

func getClientConfig(args *sshArgs, param *sshParam) (*ssh.ClientConfig, error) {
	authMethods := getAuthMethods(args, param)
	hostKeyCallback, hostKeyAlgorithms, err := getHostKeyCallback(args, param)
	if err != nil {
		return nil, err
	}
	return &ssh.ClientConfig{
		User:              param.user,
		Auth:              authMethods,
		Timeout:           getConnectTimeout(args),
		HostKeyCallback:   hostKeyCallback,
		HostKeyAlgorithms: hostKeyAlgorithms,
		BannerCallback: func(banner string) error {
			_, err := fmt.Fprint(os.Stderr, strings.ReplaceAll(banner, "\n", "\r\n"))
			return err
		},
	}, nil
}

func connectViaProxyJump(args *sshArgs, param *sshParam, config *ssh.ClientConfig) (SshClient, error) {
	debug("login to [%s] via proxy jump [%s] addr: %s", args.Destination, param.proxy.name, param.addr)
	network := getNetworkAddressFamily(args)
	conn, err := param.proxy.client.DialTimeout(network, param.addr, config.Timeout)
	if err != nil {
		return nil, fmt.Errorf("proxy jump [%s] dial [%s] [%s] failed: %v", param.proxy.name, network, param.addr, err)
	}
	ncc, chans, reqs, err := ssh.NewClientConn(&connWithTimeout{conn, config.Timeout, true}, param.addr, config)
	if err != nil {
		return nil, fmt.Errorf("proxy jump [%s] new conn [%s] failed: %v", param.proxy.name, param.addr, err)
	}
	debug("login to [%s] via proxy jump [%s] success", args.Destination, param.proxy.name)
	onExitFuncs = append(onExitFuncs, func() {
		_ = param.proxy.client.Close()
	})
	return sshNewClient(ncc, chans, reqs), nil
}

func connectViaProxyCommand(args *sshArgs, param *sshParam, config *ssh.ClientConfig) (SshClient, error) {
	conn, cmd, err := execProxyCommand(args, param)
	debug("login to [%s] via proxy command [%s] addr: %s", args.Destination, cmd, param.addr)
	if err != nil {
		return nil, fmt.Errorf("proxy command [%s] exec failed: %v", cmd, err)
	}
	ncc, chans, reqs, err := ssh.NewClientConn(conn, param.addr, config)
	if err != nil {
		return nil, fmt.Errorf("proxy command [%s] new conn [%s] failed: %v", cmd, param.addr, err)
	}
	debug("login to [%s] via proxy command [%s] success", args.Destination, cmd)
	return sshNewClient(ncc, chans, reqs), nil
}

func connectDirectly(args *sshArgs, param *sshParam, config *ssh.ClientConfig) (SshClient, error) {
	debug("login to [%s] addr: %s", args.Destination, param.addr)
	var dialer net.Dialer
	if config.Timeout > 0 {
		dialer.Timeout = config.Timeout
	}
	network := getNetworkAddressFamily(args)
	conn, err := dialer.Dial(network, param.addr)
	if err != nil {
		return nil, fmt.Errorf("login to [%s] dial [%s] [%s] failed: %v", args.Destination, network, param.addr, err)
	}
	ncc, chans, reqs, err := ssh.NewClientConn(&connWithTimeout{conn, config.Timeout, true}, param.addr, config)
	if err != nil {
		return nil, fmt.Errorf("login to [%s] new conn [%s] failed: %v", args.Destination, param.addr, err)
	}
	debug("login to [%s] success", args.Destination)
	return sshNewClient(ncc, chans, reqs), nil
}

func sshConnect(args *sshArgs, proxy *proxyJump, requireUdpMode udpModeType) (SshClient, *sshParam, error) {
	param, err := getSshParam(args)
	if err != nil {
		return nil, nil, err
	}

	resetLogLevel := setupLogLevel(args)
	defer resetLogLevel()

	if client := connectViaControl(args, param); client != nil {
		param.control = true
		return client, param, nil
	}

	config, err := getClientConfig(args, param)
	if err != nil {
		return nil, param, err
	}

	if err := setupCiphersConfig(args, config); err != nil {
		return nil, param, err
	}

	// connect via proxy jump
	if proxy != nil {
		param.proxy = proxy
		client, err := connectViaProxyJump(args, param, config)
		return client, param, err
	}

	// connect via proxy command
	if param.command != "" {
		client, err := connectViaProxyCommand(args, param, config)
		return client, param, err
	}

	// no proxy
	if len(param.proxies) == 0 {
		client, err := connectDirectly(args, param, config)
		return client, param, err
	}

	// has proxies
	udpModes := make([]udpModeType, len(param.proxies))
	for i := len(param.proxies) - 1; i >= 0; i-- {
		udpMode := getUdpMode(&sshArgs{Destination: param.proxies[i]})
		if requireUdpMode != kUdpModeNo && udpMode == kUdpModeNo {
			udpMode = requireUdpMode
		}
		if requireUdpMode == kUdpModeNo && udpMode != kUdpModeNo {
			requireUdpMode = udpMode
		}
		udpModes[i] = udpMode
	}
	for i, proxyName := range param.proxies {
		proxyArgs := &sshArgs{Destination: proxyName}
		proxyClient, proxyParam, err := sshConnect(proxyArgs, proxy, udpModes[i])
		if err != nil {
			return nil, param, err
		}
		if udpModes[i] != kUdpModeNo {
			proxyClient, err = udpConnectAsProxy(proxyArgs, proxyParam, proxyClient, udpModes[i])
			if err != nil {
				return nil, param, fmt.Errorf("udp login to proxy jump [%s] failed: %v", proxyName, err)
			}
		}
		proxy = &proxyJump{client: proxyClient, name: proxyName}
	}
	param.proxy = proxy
	client, err := connectViaProxyJump(args, param, config)
	return client, param, err
}

func keepAlive(client SshClient, args *sshArgs) {
	getOptionValue := func(option string) int {
		config := getOptionConfig(args, option)
		if config == "" {
			return 0
		}
		value, err := strconv.Atoi(config)
		if err != nil {
			warning("%s [%s] invalid: %v", option, config, err)
			return 0
		}
		return value
	}

	ssh_config.SetDefault("ServerAliveInterval", "10")
	serverAliveInterval := getOptionValue("ServerAliveInterval")
	if serverAliveInterval <= 0 {
		debug("no keep alive")
		return
	}
	serverAliveCountMax := getOptionValue("ServerAliveCountMax")
	if serverAliveCountMax <= 0 {
		serverAliveCountMax = 3
	}

	go func() {
		intervalTime := time.Duration(serverAliveInterval) * time.Second
		t := time.NewTicker(intervalTime)
		defer t.Stop()
		n := 0
		for range t.C {
			if lastTime := lastServerAliveTime.Load(); lastTime != nil && time.Since(*lastTime) < intervalTime {
				n = 0
				continue
			}
			debug("sending keep alive %d", n+1)
			if _, _, err := client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				debug("keep alive failed: %v", err)
				n++
				if n >= serverAliveCountMax {
					warning("The keep alive failures has reached ServerAliveCountMax [%s], terminating the session", serverAliveCountMax)
					_ = client.Close()
					return
				}
			} else {
				debug("keep alive successful")
				n = 0
			}
		}
	}()
}

func sshTcpLogin(args *sshArgs) (ss *sshClientSession, udpMode udpModeType, err error) {
	ss = &sshClientSession{}
	defer func() {
		if err != nil {
			ss.Close()
		} else {
			sshLoginSuccess.Store(true)
			// execute local command if necessary
			execLocalCommand(args, ss.param)
		}
	}()

	// ssh login
	udpMode = getUdpMode(args)
	ss.client, ss.param, err = sshConnect(args, nil, udpMode)
	if err != nil {
		return
	}

	// parse cmd and tty
	ss.cmd, ss.tty, err = parseCmdAndTTY(args, ss.param)
	if err != nil {
		return
	}

	// keep alive
	if !ss.param.control && udpMode == kUdpModeNo {
		keepAlive(ss.client, args)
	}

	// stdio forward runs as a proxy without port forwarding.
	// but udp mode requires a new session to start tsshd.
	if args.StdioForward != "" && udpMode == kUdpModeNo {
		return
	}

	// ssh port forwarding
	if !ss.param.control && udpMode == kUdpModeNo {
		if err = sshForward(ss.client, args, ss.param); err != nil {
			return
		}
	}

	// session is useless without executing remote command.
	// but udp mode requires a new session to start tsshd.
	if args.NoCommand && udpMode == kUdpModeNo {
		return
	}

	// new session
	ss.session, err = ss.client.NewSession()
	if err != nil {
		err = fmt.Errorf("ssh new session failed: %v", err)
		return
	}

	// for UDP connection loss notification
	if lastJumpUdpClient != nil && udpMode == kUdpModeNo {
		ss.session = lastJumpUdpClient.setMainSession(args, ss.session)
	}

	// session input and output
	ss.serverIn, err = ss.session.StdinPipe()
	if err != nil {
		err = fmt.Errorf("stdin pipe failed: %v", err)
		return
	}
	ss.serverOut, err = ss.session.StdoutPipe()
	if err != nil {
		err = fmt.Errorf("stdout pipe failed: %v", err)
		return
	}
	ss.serverErr, err = ss.session.StderrPipe()
	if err != nil {
		err = fmt.Errorf("stderr pipe failed: %v", err)
		return
	}

	if !ss.param.control && udpMode == kUdpModeNo {
		// ssh agent forward
		sshAgentForward(args, ss.param, ss.client, ss.session)
		// x11 forward
		sshX11Forward(args, ss.client, ss.session)
	}

	return
}

func sshLogin(args *sshArgs) (*sshClientSession, error) {
	ss, udpMode, err := sshTcpLogin(args)
	if err != nil {
		return nil, err
	}

	if udpMode != kUdpModeNo {
		ss, err = sshUdpLogin(args, ss, udpMode, false)
		if err != nil {
			return nil, err
		}

		if !ss.param.control && args.StdioForward == "" { // not ControlPath and not -W
			// ssh port forwarding
			if err := sshForward(ss.client, args, ss.param); err != nil {
				ss.Close()
				return nil, err
			}

			// ssh agent forward and x11 forward
			if !args.NoCommand { // not -N
				// ssh agent forward
				sshAgentForward(args, ss.param, ss.client, ss.session)
				// x11 forward
				sshX11Forward(args, ss.client, ss.session)
			}
		}
	}

	// if running as a proxy ( aka: stdio forward ), or if not executing remote command,
	// then there is no need to initialize the session, so we return early here.
	if args.StdioForward != "" || args.NoCommand {
		return ss, nil
	}

	// send and set env
	term, err := sendAndSetEnv(args, ss.session)
	if err != nil {
		ss.Close()
		return nil, err
	}

	// not terminal or not tty
	if !isTerminal || !ss.tty {
		return ss, nil
	}

	// request pty session
	width, height, err := getTerminalSize()
	if err != nil {
		ss.Close()
		return nil, fmt.Errorf("get terminal size failed: %v", err)
	}
	if term == "" {
		term = os.Getenv("TERM")
		if term == "" {
			term = "xterm-256color"
		}
	}
	if err = ss.session.RequestPty(term, height, width, ssh.TerminalModes{}); err != nil {
		ss.Close()
		return nil, fmt.Errorf("request pty failed: %v", err)
	}

	return ss, nil
}

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
	"sync"
	"sync/atomic"
	"time"

	"github.com/trzsz/shellescape"
	"golang.org/x/crypto/ssh"
)

var kDefaultConnectTimeout = 10 * time.Second

type proxyJump struct {
	client SshClient
	name   string
}

type sshParam struct {
	args    *sshArgs
	host    string
	port    string
	user    string
	addr    string
	proxies []string
	command string
	control bool
	proxy   *proxyJump
	udpMode udpModeType
	ipv4    bool
	ipv6    bool
}

func (p *sshParam) setNetworkAddressFamily(conn net.Conn) {
	remoteAddr := conn.RemoteAddr()
	tcpAddr, ok := remoteAddr.(*net.TCPAddr)
	if !ok {
		return
	}
	if tcpAddr.IP.To4() != nil {
		p.ipv4 = true
	} else if tcpAddr.IP.To16() != nil {
		p.ipv6 = true
	}
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
	param := &sshParam{args: args}

	// login dest
	destUser, destHost, destPort := parseDestination(args.Destination)
	args.Destination = destHost

	// login host
	param.host = destHost
	if hostName := getConfig(destHost, "HostName"); hostName != "" {
		var err error
		param.host, err = expandTokens(hostName, param, "%h")
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
	getProxyParam(param)

	// expand proxy
	var err error
	if param.command != "" {
		param.command, err = expandTokens(param.command, param, "%hnpr")
		if err != nil {
			return nil, fmt.Errorf("expand ProxyCommand [%s] failed: %v", param.command, err)
		}
	}
	for i := 0; i < len(param.proxies); i++ {
		param.proxies[i], err = expandTokens(strings.TrimSpace(param.proxies[i]), param, "%hnpr")
		if err != nil {
			return nil, fmt.Errorf("expand ProxyJump [%s] failed: %v", param.proxies[i], err)
		}
	}

	// udp mode
	param.udpMode = getUdpMode(args)

	return param, nil
}

func getProxyParam(param *sshParam) {
	args := param.args
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

func execProxyCommand(param *sshParam) (net.Conn, string, error) {
	command, err := expandTokens(param.command, param, "%hnpr")
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

func parseRemoteCommand(param *sshParam) (string, error) {
	args := param.args
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
	expandedCmd, err := expandTokens(command, param, "%CdhijkLlnpru")
	if err != nil {
		return "", fmt.Errorf("expand RemoteCommand [%s] failed: %v", command, err)
	}
	return expandedCmd, nil
}

func parseCmdAndTTY(param *sshParam) (cmd string, tty bool, err error) {
	cmd, err = parseRemoteCommand(param)
	if err != nil {
		return
	}

	args := param.args
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

var lastServerAliveTime atomic.Int64

type connWithTimeout struct {
	net.Conn
	timeout   time.Duration
	firstRead bool
}

func (c *connWithTimeout) Read(b []byte) (n int, err error) {
	if !c.firstRead {
		n, err = c.Conn.Read(b)
		if err == nil {
			lastServerAliveTime.Store(time.Now().UnixMilli())
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
	previousDebug, previousWarning := enableDebugLogging, enableWarningLogging
	reset := func() {
		enableDebugLogging, enableWarningLogging = previousDebug, previousWarning
	}
	if args.Debug {
		enableDebugLogging, enableWarningLogging = true, true
		return reset
	}
	switch strings.ToLower(getOptionConfig(args, "LogLevel")) {
	case "quiet", "fatal":
		enableDebugLogging, enableWarningLogging = false, false
	case "error", "info":
		enableDebugLogging, enableWarningLogging = false, true
	case "verbose", "debug", "debug1", "debug2", "debug3":
		enableDebugLogging, enableWarningLogging = true, true
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
	value, err := strconv.ParseUint(connectTimeout, 10, 32)
	if err != nil {
		warning("ConnectTimeout [%s] invalid: %v", connectTimeout, err)
		return kDefaultConnectTimeout
	}
	if value <= 0 { // set a long time to avoid issue with 0
		return 1000 * time.Hour
	}
	return time.Duration(value) * time.Second
}

func getClientConfig(param *sshParam) (*ssh.ClientConfig, error) {
	authMethods := getAuthMethods(param)
	hostKeyCallback, hostKeyAlgorithms, err := getHostKeyCallback(param)
	if err != nil {
		return nil, err
	}
	return &ssh.ClientConfig{
		User:              param.user,
		Auth:              authMethods,
		Timeout:           getConnectTimeout(param.args),
		HostKeyCallback:   hostKeyCallback,
		HostKeyAlgorithms: hostKeyAlgorithms,
		BannerCallback: func(banner string) error {
			_, err := os.Stderr.WriteString(strings.ReplaceAll(banner, "\n", "\r\n"))
			return err
		},
	}, nil
}

func connectViaProxyJump(param *sshParam, config *ssh.ClientConfig) (SshClient, error) {
	debug("login to [%s] via proxy jump [%s] addr: %s", param.args.Destination, param.proxy.name, param.addr)
	network := getNetworkAddressFamily(param.args)
	conn, err := param.proxy.client.DialTimeout(network, param.addr, config.Timeout)
	if err != nil {
		return nil, fmt.Errorf("proxy jump [%s] dial [%s] [%s] failed: %v", param.proxy.name, network, param.addr, err)
	}
	param.setNetworkAddressFamily(conn)
	ncc, chans, reqs, err := ssh.NewClientConn(&connWithTimeout{conn, config.Timeout, true}, param.addr, config)
	if err != nil {
		return nil, fmt.Errorf("proxy jump [%s] new conn [%s] failed: %v", param.proxy.name, param.addr, err)
	}
	debug("login to [%s] via proxy jump [%s] success", param.args.Destination, param.proxy.name)
	addOnExitFunc(func() {
		_ = param.proxy.client.Close()
		debug("proxy jump [%s] close completed", param.proxy.name)
	})
	return sshNewClient(ncc, chans, reqs), nil
}

func connectViaProxyCommand(param *sshParam, config *ssh.ClientConfig) (SshClient, error) {
	conn, cmd, err := execProxyCommand(param)
	debug("login to [%s] via proxy command [%s] addr: %s", param.args.Destination, cmd, param.addr)
	if err != nil {
		return nil, fmt.Errorf("proxy command [%s] exec failed: %v", cmd, err)
	}
	ncc, chans, reqs, err := ssh.NewClientConn(conn, param.addr, config)
	if err != nil {
		return nil, fmt.Errorf("proxy command [%s] new conn [%s] failed: %v", cmd, param.addr, err)
	}
	debug("login to [%s] via proxy command [%s] success", param.args.Destination, cmd)
	return sshNewClient(ncc, chans, reqs), nil
}

func connectDirectly(param *sshParam, config *ssh.ClientConfig) (SshClient, error) {
	debug("login to [%s] addr: %s", param.args.Destination, param.addr)
	var dialer net.Dialer
	if config.Timeout > 0 {
		dialer.Timeout = config.Timeout
	}
	network := getNetworkAddressFamily(param.args)
	conn, err := dialer.Dial(network, param.addr)
	if err != nil {
		return nil, fmt.Errorf("login to [%s] dial [%s] [%s] failed: %v", param.args.Destination, network, param.addr, err)
	}
	param.setNetworkAddressFamily(conn)
	ncc, chans, reqs, err := ssh.NewClientConn(&connWithTimeout{conn, config.Timeout, true}, param.addr, config)
	if err != nil {
		return nil, fmt.Errorf("login to [%s] new conn [%s] failed: %v", param.args.Destination, param.addr, err)
	}
	debug("login to [%s] success", param.args.Destination)
	return sshNewClient(ncc, chans, reqs), nil
}

func tcpLogin(param *sshParam, proxy *proxyJump, requireUDP udpModeType) (SshClient, error) {
	// ssh multiplexing
	if client := connectViaControl(param); client != nil {
		param.control = true
		return client, nil
	}

	// init config
	config, err := getClientConfig(param)
	if err != nil {
		return nil, err
	}
	if err := setupCiphersConfig(param.args, config); err != nil {
		return nil, err
	}

	// connect via proxy jump
	if proxy != nil {
		param.proxy = proxy
		client, err := connectViaProxyJump(param, config)
		return client, err
	}

	// connect via proxy command
	if param.command != "" {
		client, err := connectViaProxyCommand(param, config)
		return client, err
	}

	// no proxy
	if len(param.proxies) == 0 {
		client, err := connectDirectly(param, config)
		return client, err
	}

	// has proxies
	udpModes := make([]udpModeType, len(param.proxies))
	for i := len(param.proxies) - 1; i >= 0; i-- { // init proxy udp mode
		proxyArgs := &sshArgs{Destination: param.proxies[i]}
		udpMode := getUdpMode(proxyArgs)
		if requireUDP != kUdpModeNo && udpMode == kUdpModeNo {
			udpMode = requireUDP
		}
		if requireUDP == kUdpModeNo && udpMode != kUdpModeNo {
			initGlobalUdpAliveTimeout(proxyArgs)
			requireUDP = udpMode
		}
		udpModes[i] = udpMode
	}
	for i, proxyName := range param.proxies { // proxy login
		proxyParam, err := getSshParam(&sshArgs{Destination: proxyName})
		if err != nil {
			return nil, err
		}
		proxyClient, err := sshLogin(proxyParam, proxy, udpModes[i])
		if err != nil {
			return nil, err
		}
		proxy = &proxyJump{client: proxyClient, name: proxyName}
	}
	param.proxy = proxy
	client, err := connectViaProxyJump(param, config)
	return client, err
}

func sshLogin(param *sshParam, proxy *proxyJump, requireUDP udpModeType) (SshClient, error) {
	// init udp mode
	if requireUDP != kUdpModeNo && param.udpMode == kUdpModeNo {
		param.udpMode = requireUDP
	}
	if requireUDP == kUdpModeNo && param.udpMode != kUdpModeNo {
		initGlobalUdpAliveTimeout(param.args)
		requireUDP = param.udpMode
	}

	// setup log level
	resetLogLevel := setupLogLevel(param.args)
	defer resetLogLevel()

	// tcp login
	tcpClient, err := tcpLogin(param, proxy, requireUDP)
	if err != nil {
		return nil, err
	}
	if param.udpMode == kUdpModeNo {
		return tcpClient, nil
	}

	// udp login
	return udpLogin(param, tcpClient)
}

func keepAlive(sshConn *sshConnection) {
	serverAliveInterval := uint32(0)
	if c := getOptionConfig(sshConn.param.args, "ServerAliveInterval"); c != "" {
		v, err := strconv.ParseUint(c, 10, 32)
		if err != nil {
			warning("ServerAliveInterval [%s] is invalid: %v", c, err)
		} else {
			serverAliveInterval = uint32(v)
		}
	}
	if serverAliveInterval == 0 {
		debug("no keep alive for [%s]", sshConn.param.args.Destination)
		return
	}

	serverAliveCountMax := uint32(3)
	if c := getOptionConfig(sshConn.param.args, "ServerAliveCountMax"); c != "" {
		v, err := strconv.ParseUint(c, 10, 32)
		if err != nil {
			warning("ServerAliveCountMax [%s] is invalid: %v", c, err)
		} else {
			serverAliveCountMax = uint32(v)
		}
	}

	sendKeepAlive := func(idx int) {
		debug("keep alive [%d] sending", idx)
		if _, _, err := sshConn.client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
			if !isClosedError(err) {
				debug("keep alive [%d] failed: %v", idx, err)
			}
			return
		}
		debug("keep alive [%d] success", idx)
	}

	go func() {
		lastServerAliveTime.Store(time.Now().UnixMilli())
		concurrent := make(chan struct{}, 2) // do not close to prevent writing after closing
		aliveTimeout := int64(serverAliveInterval) * int64(serverAliveCountMax) * 1000
		intervalTime := int64(serverAliveInterval)*1000 - 300 // send keep alive a little earlier

		for {
			sleepTime := lastServerAliveTime.Load() + intervalTime - time.Now().UnixMilli()
			if sleepTime > 0 {
				time.Sleep(time.Duration(sleepTime) * time.Millisecond)
				continue
			}

			n := 1
			go sendKeepAlive(n)

			ticker := time.NewTicker(time.Duration(intervalTime) * time.Millisecond)
			for range ticker.C {
				sleepTime = lastServerAliveTime.Load() + intervalTime - time.Now().UnixMilli()
				if sleepTime > 0 {
					ticker.Stop()
					time.Sleep(time.Duration(sleepTime) * time.Millisecond)
					break
				}

				if aliveTimeout > 0 && time.Now().UnixMilli()-lastServerAliveTime.Load() > aliveTimeout {
					ticker.Stop()
					sshConn.forceExit(kExitCodeKeepAlive, fmt.Sprintf(
						"Exit due to keep alive timeout [%ds], ServerAliveInterval [%d], ServerAliveCountMax [%d]",
						aliveTimeout/1000, serverAliveInterval, serverAliveCountMax))
					return
				}

				n++
				select {
				case concurrent <- struct{}{}:
					go func() {
						sendKeepAlive(n)
						<-concurrent
					}()
				default:
					debug("keep alive [%d] dropped (concurrent limit)", n)
				}
			}
		}
	}()
}

func sshConnect(args *sshArgs) (*sshConnection, error) {
	// init log level
	_ = setupLogLevel(args)

	// init ssh param
	param, err := getSshParam(args)
	if err != nil {
		return nil, err
	}

	// parse cmd and tty
	cmd, tty, err := parseCmdAndTTY(param)
	if err != nil {
		return nil, err
	}

	// ssh login
	client, err := sshLogin(param, nil, kUdpModeNo)
	if err != nil {
		return nil, err
	}
	sshLoginSuccess.Store(true)

	sshConn := &sshConnection{
		exitChan: make(chan int, 1),
		client:   client,
		param:    param,
		cmd:      cmd,
		tty:      tty,
	}

	// init global sshConn for udp mode
	if lastJumpUdpClient != nil {
		lastJumpUdpClient.sshConn = sshConn
	}

	// tcp keep alive
	if !param.control && param.udpMode == kUdpModeNo {
		keepAlive(sshConn)
	}

	//  cleanup
	cleanupAfterLogin()

	return sshConn, nil
}

var afterLoginFuncs []func()
var afterLoginMutex sync.Mutex

func cleanupAfterLogin() {
	afterLoginMutex.Lock()
	defer afterLoginMutex.Unlock()
	for i := len(afterLoginFuncs) - 1; i >= 0; i-- {
		afterLoginFuncs[i]()
	}
	afterLoginFuncs = nil
}

func addAfterLoginFunc(f func()) {
	afterLoginMutex.Lock()
	defer afterLoginMutex.Unlock()
	afterLoginFuncs = append(afterLoginFuncs, f)
}

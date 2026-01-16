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
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/trzsz/tsshd/tsshd"
	"golang.org/x/crypto/ssh"
)

const kDefaultUdpAliveTimeout = 24 * time.Hour

const kDefaultUdpHeartbeatTimeout = 3 * time.Second

const kDefaultUdpReconnectTimeout = 15 * time.Second

type udpModeType int

const (
	kUdpModeNo udpModeType = iota
	kUdpModeYes
	kUdpModeKcp
	kUdpModeQuic
)

func (t udpModeType) String() string {
	return [...]string{
		"No",
		"Yes",
		"KCP",
		"QUIC",
	}[t]
}

type sshUdpClient struct {
	*tsshd.SshUdpClient
	proxyClient      *sshUdpClient
	intervalTime     time.Duration
	aliveTimeout     time.Duration
	connectTimeout   time.Duration
	reconnectTimeout time.Duration
	waitCloseChan    chan struct{}
	showNotifMutex   sync.Mutex
	notifInterceptor *notifInterceptor
	notifModel       atomic.Pointer[notifModel]
	sshDestName      string
	sshConn          atomic.Pointer[sshConnection]
}

func (c *sshUdpClient) NewSession() (SshSession, error) {
	return c.SshUdpClient.NewSession()
}

func (c *sshUdpClient) DialTimeout(network, addr string, timeout time.Duration) (net.Conn, error) {
	return c.SshUdpClient.DialTimeout(network, addr, timeout)
}

func (c *sshUdpClient) Close() error {
	err := c.SshUdpClient.Close()
	if c.waitCloseChan != nil {
		select {
		case c.waitCloseChan <- struct{}{}:
		default:
		}
	}
	return err
}

func (c *sshUdpClient) Wait() error {
	if c.waitCloseChan != nil {
		<-c.waitCloseChan
	}
	return c.SshUdpClient.Wait()
}

func (c *sshUdpClient) exit(code int, cause string) {
	if notif := c.notifModel.Load(); notif != nil {
		notif.clientExiting.Store(true)
		notif.renderView(true, false)
	}
	c.sshConn.Load().forceExit(code, cause)
}

func (c *sshUdpClient) debug(format string, a ...any) {
	if !enableDebugLogging {
		return
	}
	msg := fmt.Sprintf(format, a...)
	writeDebugLog(time.Now().UnixMilli(), c.sshDestName, msg)
}

func (c *sshUdpClient) isReconnectTimeout() bool {
	return time.Since(time.UnixMilli(c.GetLastActiveTime())) > c.reconnectTimeout
}

func (c *sshUdpClient) udpKeepAlive() {
	for !c.IsClosed() {
		if c.sshConn.Load() != nil && time.Since(time.UnixMilli(c.GetLastActiveTime())) > c.aliveTimeout {
			c.debug("alive timeout for %v", c.aliveTimeout)
			c.exit(kExitCodeUdpTimeout, fmt.Sprintf("Exit due to connection was lost and timeout for %v", c.aliveTimeout))
			return
		}

		if isTerminal && c.sshConn.Load() != nil && enableWarningLogging && c.isReconnectTimeout() {
			go c.notifyConnectionLost()
		}

		time.Sleep(c.intervalTime)
	}
}

func (c *sshUdpClient) getConnLostStatus() string {
	return fmt.Sprintf("Oops, looks like the connection to the server was lost, trying to reconnect for %d/%d seconds.",
		time.Since(time.UnixMilli(c.GetLastActiveTime()))/time.Second, c.aliveTimeout/time.Second)
}

func (c *sshUdpClient) notifyConnectionLost() {
	if !c.showNotifMutex.TryLock() {
		return
	}
	defer c.showNotifMutex.Unlock()
	if !c.isReconnectTimeout() {
		return
	}

	if c.notifInterceptor == nil {
		_, _ = os.Stderr.WriteString(ansi.HideCursor)
		for c.isReconnectTimeout() && !c.sshConn.Load().exited.Load() {
			fmt.Fprintf(os.Stderr, "\r\033[0;33m%s\033[0m\x1b[K", c.getConnLostStatus())
			time.Sleep(time.Second)
		}
		if !c.isReconnectTimeout() && !c.sshConn.Load().exited.Load() {
			fmt.Fprintf(os.Stderr, "\r\033[0;32m%s\033[0m\x1b[K\r\n", "Congratulations, you have successfully reconnected to the server.")
		}
		_, _ = os.Stderr.WriteString(ansi.ShowCursor)
		return
	}

	showConnectionLostNotif(c)
}

func (c *sshUdpClient) discardPendingInput(discardMarker []byte) {
	if c.notifInterceptor == nil {
		return
	}
	if input := c.notifInterceptor.discardPendingInput(discardMarker); len(input) > 0 {
		if enableDebugLogging {
			c.debug("[client] discard input: %s", strconv.QuoteToASCII(string(input)))
		}
		if isRunningTmuxIntegration() {
			handleTmuxDiscardedInput(input)
		}
	}
}

var lastJumpUdpClient *sshUdpClient
var globalUdpAliveTimeout time.Duration

func quitCallback(name, reason string) {
	for lastJumpUdpClient == nil || lastJumpUdpClient.sshConn.Load() == nil {
		time.Sleep(10 * time.Millisecond) // waiting for sshConn to be initialized
	}
	lastJumpUdpClient.sshConn.Load().forceExit(kExitCodeSignalKill, fmt.Sprintf("Exit due to [%s] %s", name, reason))
}

func initGlobalUdpAliveTimeout(args *sshArgs) {
	if globalUdpAliveTimeout != 0 {
		warning("global udp alive timeout [%v] has already been initialized", globalUdpAliveTimeout)
		return
	}
	globalUdpAliveTimeout = getUdpTimeoutConfig(args, "UdpAliveTimeout", kDefaultUdpAliveTimeout)
	debug("init global udp alive timeout [%v] for [%s]", globalUdpAliveTimeout, args.Destination)
}

func udpLogin(param *sshParam, tcpClient SshClient) (SshClient, error) {
	defer func() { _ = tcpClient.Close() }()

	args := param.args
	debug("udp login to [%s] using UDP mode: %s", args.Destination, param.udpMode)

	if enableDebugLogging {
		if initDebugLogFile() && maxHostNameLength == 0 {
			debug("udp debug logs are written to \x1b[0;35m%s\x1b[0m", debugLogFileName)
		}
		maxHostNameLength = max(maxHostNameLength, len(args.Destination))
	}

	mtu := uint16(0)
	var proxyClient *sshUdpClient
	if param.proxy != nil {
		var ok bool
		proxyClient, ok = param.proxy.client.(*sshUdpClient)
		if !ok {
			return nil, fmt.Errorf("proxy client [%T] for [%s] is not a udp client", param.proxy.client, args.Destination)
		}
		mtu = proxyClient.GetMaxDatagramSize()
	}

	// start tsshd
	connectTimeout := getConnectTimeout(args)
	tsshdCmd := getTsshdCommand(param, mtu, connectTimeout)
	debug("udp login to [%s] tsshd command: %s", args.Destination, tsshdCmd)

	serverInfo, err := startTsshdServer(tcpClient, tsshdCmd)
	if err != nil {
		return nil, fmt.Errorf("udp login to [%s] start tsshd on remote failed: %v", args.Destination, err)
	}

	// udp config
	if globalUdpAliveTimeout == 0 {
		warning("global udp alive timeout for [%s] has not been initialized yet", args.Destination)
		initGlobalUdpAliveTimeout(param.args)
	}
	heartbeatTimeout := getUdpTimeoutConfig(args, "UdpHeartbeatTimeout", kDefaultUdpHeartbeatTimeout)
	reconnectTimeout := getUdpTimeoutConfig(args, "UdpReconnectTimeout", kDefaultUdpReconnectTimeout)
	// Ensure at least 10 keep-alive attempts before exiting on timeout,
	// and at least 3 attempts before reconnect or showing a connection lost notification.
	intervalTime := min(globalUdpAliveTimeout/10, min(heartbeatTimeout, reconnectTimeout)/3)
	debug("udp keep alive interval time [%v] for [%s]", intervalTime, args.Destination)

	// new udp client
	udpClient := &sshUdpClient{
		proxyClient:      proxyClient,
		intervalTime:     intervalTime,
		aliveTimeout:     globalUdpAliveTimeout,
		connectTimeout:   connectTimeout,
		reconnectTimeout: reconnectTimeout,
		sshDestName:      args.Destination,
	}
	tsshdAddr := joinHostPort(param.host, strconv.Itoa(serverInfo.Port))
	clientOpts := &tsshd.UdpClientOptions{
		EnableDebugging:  enableDebugLogging,
		EnableWarning:    enableWarningLogging,
		IPv4:             param.ipv4,
		IPv6:             param.ipv6,
		TsshdAddr:        tsshdAddr,
		ServerInfo:       serverInfo,
		AliveTimeout:     globalUdpAliveTimeout,
		IntervalTime:     intervalTime,
		ConnectTimeout:   connectTimeout,
		HeartbeatTimeout: heartbeatTimeout,
		DebugFunc:        func(msec int64, msg string) { writeDebugLog(msec, args.Destination, msg) },
		WarningFunc:      func(msg string) { warning("udp [%s] %s", args.Destination, msg) },
		QuitCallback:     func(reason string) { quitCallback(args.Destination, reason) },
		DiscardCallback: func(discardMarker, discardedInput []byte) {
			if len(discardMarker) > 0 {
				udpClient.discardPendingInput(discardMarker)
			}
			if len(discardedInput) > 0 && isRunningTmuxIntegration() {
				handleTmuxDiscardedInput(discardedInput)
			}
		},
	}

	if param.proxy != nil {
		clientOpts.ProxyClient = proxyClient.SshUdpClient
		debug("udp login to [%s] via proxy jump [%s] addr: %s", args.Destination, param.proxy.name, tsshdAddr)
	} else {
		debug("udp login to [%s] tsshd server addr: %s", param.args.Destination, tsshdAddr)
	}

	udpClient.SshUdpClient, err = tsshd.NewSshUdpClient(clientOpts)
	if err != nil {
		return nil, fmt.Errorf("udp login to [%s] failed: %v", args.Destination, err)
	}
	debug("udp login to [%s] success", args.Destination)

	lastJumpUdpClient = udpClient

	// preventing exit for just forwarding ports
	if args.NoCommand || args.Background {
		udpClient.waitCloseChan = make(chan struct{}, 1)
	}

	// udp keep alive
	go udpClient.udpKeepAlive()

	return udpClient, nil
}

func startTsshdServer(tcpClient SshClient, tsshdCmd string) (*tsshd.ServerInfo, error) {
	session, err := tcpClient.NewSession()
	if err != nil {
		return nil, fmt.Errorf("new session failed: %v", err)
	}
	defer func() { _ = session.Close() }()
	serverOut, err := session.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe failed: %v", err)
	}
	serverErr, err := session.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("stderr pipe failed: %v", err)
	}
	if err := session.RequestPty("xterm-256color", 200, 800, ssh.TerminalModes{}); err != nil {
		return nil, fmt.Errorf("request pty for tsshd failed: %v", err)
	}

	if err := session.Start(tsshdCmd); err != nil {
		return nil, fmt.Errorf("session start failed: %v", err)
	}

	if err := session.Wait(); err != nil {
		var builder strings.Builder
		if outMsg, _ := readConsoleOutput(serverOut); outMsg != "" {
			builder.WriteString(outMsg)
		}
		if errMsg, _ := readConsoleOutput(serverErr); errMsg != "" {
			if builder.Len() > 0 {
				builder.WriteString("\n")
			}
			builder.WriteString(errMsg)
		}
		if builder.Len() == 0 {
			builder.WriteString(fmt.Sprintf("session wait failed: %v", err))
		}
		return nil, fmt.Errorf("%s\r\n%s", builder.String(),
			"\033[0;36mHint:\033[0m Have you installed tsshd on your server? You may need to specify the path to tsshd.")
	}

	output, err := readConsoleOutput(serverOut)
	if output == "" {
		if errMsg, _ := readConsoleOutput(serverErr); errMsg != "" {
			return nil, fmt.Errorf("stdout is empty, stderr output: %s", errMsg)
		}
		if err != nil {
			return nil, fmt.Errorf("read stdout output failed: %v", err)
		}
		return nil, fmt.Errorf("stdout and stderr are both empty")
	}

	pos := strings.LastIndexByte(output, '\a')
	if pos >= 0 {
		output = output[pos+1:]
	}
	pos = strings.IndexByte(output, '{')
	if pos >= 0 {
		output = output[pos:]
	}
	pos = strings.LastIndexByte(output, '}')
	if pos >= 0 {
		output = output[:pos+1]
	}
	output = strings.ReplaceAll(output, "\r", "")
	output = strings.ReplaceAll(output, "\n", "")
	if !strings.HasPrefix(output, "{") || !strings.HasSuffix(output, "}") {
		return nil, fmt.Errorf("unexpected stdout output: %s", strconv.QuoteToASCII(output))
	}

	var info tsshd.ServerInfo
	if err := json.Unmarshal([]byte(output), &info); err != nil {
		return nil, fmt.Errorf("json unmarshal [%s] failed: %v", strconv.QuoteToASCII(output), err)
	}

	return &info, nil
}

func getTsshdCommand(param *sshParam, mtu uint16, connectTimeout time.Duration) string {
	args := param.args
	var buf strings.Builder
	if args.TsshdPath != "" {
		buf.WriteString(args.TsshdPath)
	} else if tsshdPath := getExOptionConfig(args, "TsshdPath"); tsshdPath != "" {
		buf.WriteString(tsshdPath)
	} else {
		buf.WriteString("tsshd")
	}

	if param.udpMode == kUdpModeKcp {
		buf.WriteString(" --kcp")
	}
	if udpProxyMode := strings.ToLower(getExOptionConfig(args, "UdpProxyMode")); udpProxyMode == "tcp" {
		buf.WriteString(" --tcp")
	}
	if enableDebugLogging {
		buf.WriteString(" --debug")
	}

	network := getNetworkAddressFamily(args)
	if strings.HasSuffix(network, "4") {
		buf.WriteString(" --ipv4")
	}
	if strings.HasSuffix(network, "6") {
		buf.WriteString(" --ipv6")
	}

	if mtu > 0 {
		buf.WriteString(" --mtu ")
		buf.WriteString(fmt.Sprintf("%d", mtu))
	}

	tsshdPort := args.TsshdPort
	if tsshdPort == "" {
		tsshdPort = getExOptionConfig(args, "TsshdPort")
	}
	if tsshdPort == "" {
		tsshdPort = getExOptionConfig(args, "UdpPort") // backward compatibility
	}
	if tsshdPort != "" {
		ranges := parseTsshdPortRanges(tsshdPort)
		if len(ranges) > 0 {
			buf.WriteString(" --port ")
			for i, r := range ranges {
				if i > 0 {
					buf.WriteByte(',')
				}
				if r[0] == r[1] {
					buf.WriteString(fmt.Sprintf("%d", r[0]))
				} else {
					buf.WriteString(fmt.Sprintf("%d-%d", r[0], r[1]))
				}
			}
		}
	}

	if connectTimeout != kDefaultConnectTimeout {
		buf.WriteString(" --connect-timeout ")
		buf.WriteString(fmt.Sprintf("%d", connectTimeout/time.Second))
	}

	return buf.String()
}

func parseTsshdPortRanges(tsshdPort string) [][2]uint16 {
	var ranges [][2]uint16

	addPortRange := func(lowPort string, highPort *string) {
		low, err := strconv.ParseUint(lowPort, 10, 16)
		if err != nil || low == 0 {
			warning("tsshd port [%s] invalid: port [%s] is not a value in [1, 65535]", tsshdPort, lowPort)
			return
		}
		high := low
		if highPort != nil {
			high, err = strconv.ParseUint(*highPort, 10, 16)
			if err != nil || high == 0 {
				warning("tsshd port [%s] invalid: port [%s] is not a value in [1, 65535]", tsshdPort, *highPort)
				return
			}
		}
		if low > high {
			warning("tsshd port [%s] invalid: port range [%d-%d] is invalid (low > high)", tsshdPort, low, high)
			return
		}
		ranges = append(ranges, [2]uint16{uint16(low), uint16(high)})
	}

	for seg := range strings.SplitSeq(tsshdPort, ",") {
		tokens := strings.Fields(seg)
		k := -1
		for i := 0; i < len(tokens); i++ {
			token := tokens[i]
			// Case 1: combined form like "8000-9000"
			if strings.Contains(token, "-") && token != "-" {
				parts := strings.Split(token, "-")
				if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
					warning("tsshd port [%s] invalid: malformed port range [%s]", tsshdPort, token)
					continue
				}
				addPortRange(parts[0], &parts[1])
				continue
			}
			// Case 2: single "-"
			if token == "-" {
				if i == 0 || i+1 >= len(tokens) || i-1 <= k {
					warning("tsshd port [%s] invalid: '-' must appear between two ports", tsshdPort)
					i++
					continue
				}
				addPortRange(tokens[i-1], &tokens[i+1])
				k = i + 1
				i++ // skip high
				continue
			}
			// Case 3: part of a range: skip (handled by '-')
			if i+1 < len(tokens) && tokens[i+1] == "-" {
				continue
			}
			// Case 4: plain number
			if i > 0 && tokens[i-1] == "-" {
				warning("tsshd port [%s] invalid: malformed port range [- %s]", tsshdPort, token)
				continue
			}
			addPortRange(token, nil)
		}
	}

	return ranges
}

func readConsoleOutput(stream io.Reader) (string, error) {
	var buf bytes.Buffer
	_, err := buf.ReadFrom(stream)
	out := strings.TrimSpace(ansi.Strip(buf.String()))
	return out, err
}

func getUdpTimeoutConfig(args *sshArgs, timeoutOption string, defaultTimeout time.Duration) time.Duration {
	timeoutConfig := getExOptionConfig(args, timeoutOption)
	if timeoutConfig == "" {
		return defaultTimeout
	}
	timeoutSeconds, err := strconv.ParseUint(timeoutConfig, 10, 32)
	if err != nil {
		warning("%s [%s] invalid: %v", timeoutOption, timeoutConfig, err)
		return defaultTimeout
	}
	if timeoutSeconds <= 0 {
		warning("%s [%d] must be greater than 0", timeoutOption, timeoutSeconds)
		return defaultTimeout
	}
	return time.Duration(timeoutSeconds) * time.Second
}

func getUdpMode(args *sshArgs) udpModeType {
	if udpMode := args.Option.get("UdpMode"); udpMode != "" {
		switch strings.ToLower(udpMode) {
		case "no":
			if args.UDP || args.KCP {
				warning("disable UDP mode since -oUdpMode=No")
			}
			return kUdpModeNo
		case "yes":
			return kUdpModeYes
		case "kcp":
			return kUdpModeKcp
		case "quic":
			return kUdpModeQuic
		default:
			warning("unknown UdpMode %s", udpMode)
		}
	}

	if args.KCP {
		return kUdpModeKcp
	}

	udpMode := getExConfig(args.Destination, "UdpMode")
	switch strings.ToLower(udpMode) {
	case "", "no":
		break
	case "yes":
		return kUdpModeYes
	case "kcp":
		return kUdpModeKcp
	case "quic":
		return kUdpModeQuic
	default:
		warning("unknown UdpMode %s", udpMode)
	}

	if args.UDP {
		return kUdpModeYes
	}
	return kUdpModeNo
}

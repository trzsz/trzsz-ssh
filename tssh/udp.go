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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

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
	heartbeatTimeout time.Duration
	reconnectTimeout time.Duration
	waitCloseChan    chan struct{}
	lastAliveTime    atomic.Int64
	reconnectMutex   sync.Mutex
	reconnectError   atomic.Pointer[error]
	showNotifMutex   sync.Mutex
	notifInterceptor *notifInterceptor
	notifModel       atomic.Pointer[notifModel]
	usingProxy       bool
	sshDestName      string
	offlineFlag      atomic.Bool
	sshConn          *sshConnection
}

func (c *sshUdpClient) NewSession() (SshSession, error) {
	return c.SshUdpClient.NewSession()
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
	c.sshConn.forceExit(code, cause)
}

func (c *sshUdpClient) debug(format string, a ...any) {
	if !enableDebugLogging {
		return
	}
	msg := fmt.Sprintf(format, a...)
	writeDebugLog(time.Now().UnixMilli(), c.sshDestName, msg)
}

func (c *sshUdpClient) isHeartbeatTimeout() bool {
	offline := time.Since(time.UnixMilli(c.lastAliveTime.Load())) > c.heartbeatTimeout
	if enableDebugLogging {
		if offline {
			if c.offlineFlag.CompareAndSwap(false, true) {
				c.debug("udp transport offline (%dms)", time.Since(time.UnixMilli(c.lastAliveTime.Load()))/time.Millisecond)
			}
		} else {
			if c.offlineFlag.CompareAndSwap(true, false) {
				c.debug("comes back online successfully")
			}
		}
	}
	return offline
}

func (c *sshUdpClient) isReconnectTimeout() bool {
	return time.Since(time.UnixMilli(c.lastAliveTime.Load())) > c.reconnectTimeout
}

func (c *sshUdpClient) udpKeepAlive() {
	ackChan := make(chan int64, 2) // do not close to prevent writing after closing
	aliveCallback := func(aliveTime int64) {
		if c.IsClosed() {
			return
		}

		if aliveTime == 0 {
			if enableDebugLogging && c.isHeartbeatTimeout() {
				c.debug("received ping response from the server")
			}
			c.lastAliveTime.Store(time.Now().UnixMilli())
			select {
			case ackChan <- 0:
			default:
			}
			return
		}

		if enableDebugLogging && c.isHeartbeatTimeout() {
			c.debug("keep alive response [%d]: %v", aliveTime, time.UnixMilli(aliveTime).Format("15:04:05.000"))
		}
		if aliveTime > c.lastAliveTime.Load() {
			c.lastAliveTime.Store(aliveTime)
		}
		ackChan <- aliveTime
	}

	ticker := time.NewTicker(c.intervalTime)
	defer ticker.Stop()
	go func() {
		for range ticker.C {
			aliveTime := time.Now().UnixMilli()
			if enableDebugLogging && c.isHeartbeatTimeout() {
				c.debug("sending keep alive [%d]", aliveTime)
			}
			err := c.KeepAlive(aliveTime, aliveCallback)
			if err != nil {
				warning("udp [%s] keep alive failed: %v", c.sshDestName, err)
			}
			if enableDebugLogging && c.isHeartbeatTimeout() {
				c.debug("keep alive [%d] sent: %v", aliveTime, err)
			}
			for {
				ackAliveTime := <-ackChan
				if ackAliveTime == aliveTime || ackAliveTime == 0 {
					break
				}
			}
		}
	}()

	for !c.IsClosed() {
		if c.sshConn != nil && time.Since(time.UnixMilli(c.lastAliveTime.Load())) > c.aliveTimeout {
			c.debug("alive timeout for %v", c.aliveTimeout)
			c.exit(kExitCodeUdpTimeout, fmt.Sprintf("Exit due to connection was lost and timeout for %v", c.aliveTimeout))
			return
		}

		if c.usingProxy && c.isHeartbeatTimeout() {
			go c.tryToReconnect()
		}

		if isTerminal && enableWarningLogging && c.sshConn != nil && c.isReconnectTimeout() {
			go c.notifyConnectionLost()
		}

		time.Sleep(c.intervalTime)
	}
}

func (c *sshUdpClient) tryToReconnect() {
	if !c.reconnectMutex.TryLock() {
		return
	}
	defer c.reconnectMutex.Unlock()

	if c.proxyClient != nil {
		// prioritize allowing the proxy to reconnect first
		time.Sleep(c.proxyClient.intervalTime)

		if c.proxyClient.isHeartbeatTimeout() {
			// wait for the proxy to reconnect first
			for c.proxyClient.isHeartbeatTimeout() {
				time.Sleep(c.intervalTime)
			}
			// wait for auto-recovery after proxy reconnection
			time.Sleep(c.intervalTime*2 + 200*time.Millisecond)
		}
	}

	if !c.isHeartbeatTimeout() {
		return
	}

	c.debug("attempting new transport path")
	if err := c.Reconnect(c.connectTimeout); err != nil {
		c.debug("reconnect failed: %v", err)
		c.reconnectError.Store(&err)
		time.Sleep(c.intervalTime) // don't reconnect too frequently
		return
	}

	c.debug("new transport path established")
	c.reconnectError.Store(nil)

	// give heartbeat some time
	for {
		sleepTime := time.Until(time.UnixMilli(c.GetLastOutputTime()).Add(c.heartbeatTimeout))
		if sleepTime < time.Millisecond {
			break
		}
		time.Sleep(sleepTime)
	}
}

func (c *sshUdpClient) getConnLostStatus() string {
	var format string
	if c.usingProxy {
		format = "Oops, looks like the connection to the server was lost, trying to reconnect for %d/%d seconds."
	} else {
		format = "Oops, looks like the connection to the server was lost, automatically exit countdown %d/%d seconds."
	}
	return fmt.Sprintf(format, time.Since(time.UnixMilli(c.lastAliveTime.Load()))/time.Second, c.aliveTimeout/time.Second)
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
		for c.isReconnectTimeout() && !c.sshConn.exited.Load() {
			fmt.Fprintf(os.Stderr, "\r\033[0;33m%s\033[0m\x1b[K", c.getConnLostStatus())
			time.Sleep(time.Second)
		}
		if !c.isReconnectTimeout() && !c.sshConn.exited.Load() {
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
	for lastJumpUdpClient == nil || lastJumpUdpClient.sshConn == nil {
		time.Sleep(10 * time.Millisecond) // waiting for sshConn to be initialized
	}
	lastJumpUdpClient.sshConn.forceExit(kExitCodeSignalKill, fmt.Sprintf("Exit due to [%s] %s", name, reason))
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
		if initDebugLogFile() == nil && debugLogFile != nil && maxHostNameLength == 0 {
			debug("udp debug logs are written to \x1b[0;35m%s\x1b[0m", debugLogFile.Name())
		}
		maxHostNameLength = max(maxHostNameLength, len(args.Destination))
	}

	// start tsshd
	connectTimeout := getConnectTimeout(args)
	udpProxyMode := getExOptionConfig(args, "UdpProxyMode")
	usingProxy := strings.ToLower(udpProxyMode) != "no"
	tsshdCmd := getTsshdCommand(param, udpProxyMode, connectTimeout)
	debug("udp login to [%s] tsshd command: %s", args.Destination, tsshdCmd)

	serverInfo, err := startTsshdServer(tcpClient, tsshdCmd)
	if err != nil {
		return nil, fmt.Errorf("udp login to [%s] start tsshd failed: %v", args.Destination, err)
	}

	// udp config
	if globalUdpAliveTimeout == 0 {
		warning("global udp alive timeout for [%s] has not been initialized yet", args.Destination)
		initGlobalUdpAliveTimeout(param.args)
	}
	heartbeatTimeout := getUdpTimeoutConfig(args, "UdpHeartbeatTimeout", kDefaultUdpHeartbeatTimeout)
	reconnectTimeout := getUdpTimeoutConfig(args, "UdpReconnectTimeout", kDefaultUdpReconnectTimeout)
	var intervalTime time.Duration
	if usingProxy {
		intervalTime = min(globalUdpAliveTimeout/10, min(heartbeatTimeout, reconnectTimeout)/5, 1*time.Second)
	} else {
		intervalTime = min(globalUdpAliveTimeout/10, 10*time.Second)
	}

	tsshdAddr := joinHostPort(param.host, strconv.Itoa(serverInfo.Port))
	debug("udp login to [%s] tsshd server addr: %s", param.args.Destination, tsshdAddr)

	// proxy forward
	var proxyClient *sshUdpClient
	if param.proxy != nil {
		var ok bool
		proxyClient, ok = param.proxy.client.(*sshUdpClient)
		if !ok {
			return nil, fmt.Errorf("proxy client [%T] for [%s] is not a udp client", param.proxy.client, args.Destination)
		}
		localAddr, err := proxyClient.ForwardUDPv1(tsshdAddr, max(connectTimeout, heartbeatTimeout, reconnectTimeout))
		if err != nil {
			return nil, fmt.Errorf("udp login to [%s] forward udp [%s] failed: %v", args.Destination, tsshdAddr, err)
		}
		debug("udp login to [%s] proxy jump: %s <=> [%s] <=> %s", args.Destination, localAddr, param.proxy.name, tsshdAddr)
		tsshdAddr = localAddr
	}

	// new udp client
	udpClient := &sshUdpClient{
		proxyClient:      proxyClient,
		intervalTime:     intervalTime,
		aliveTimeout:     globalUdpAliveTimeout,
		connectTimeout:   connectTimeout,
		heartbeatTimeout: heartbeatTimeout,
		reconnectTimeout: reconnectTimeout,
		sshDestName:      args.Destination,
		usingProxy:       usingProxy,
	}

	udpClient.SshUdpClient, err = tsshd.NewSshUdpClient(&tsshd.UdpClientOptions{
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
	})
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
	udpClient.lastAliveTime.Store(time.Now().UnixMilli())
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
		return nil, fmt.Errorf("start tsshd failed: %v", err)
	}
	if err := session.Wait(); err != nil {
		var builder strings.Builder
		if outMsg := readFromStream(serverOut); outMsg != "" {
			builder.WriteString(outMsg)
		}
		if errMsg := readFromStream(serverErr); errMsg != "" {
			if builder.Len() > 0 {
				builder.WriteString("\n")
			}
			builder.WriteString(errMsg)
		}
		if builder.Len() == 0 {
			builder.WriteString(err.Error())
		}
		return nil, fmt.Errorf("(Have you installed tsshd on your server? You may need to specify the path to tsshd.)\r\n"+
			"run tsshd failed: %s", builder.String())
	}

	output := readFromStream(serverOut)
	if output == "" {
		if errMsg := readFromStream(serverErr); errMsg != "" {
			return nil, fmt.Errorf("run tsshd failed: %s", errMsg)
		}
		return nil, fmt.Errorf("run tsshd failed: the output is empty")
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
		return nil, fmt.Errorf("run tsshd failed: %s", strconv.QuoteToASCII(output))
	}

	var info tsshd.ServerInfo
	if err := json.Unmarshal([]byte(output), &info); err != nil {
		return nil, fmt.Errorf("json unmarshal [%s] failed: %v", strconv.QuoteToASCII(output), err)
	}

	return &info, nil
}

func getTsshdCommand(param *sshParam, udpProxyMode string, connectTimeout time.Duration) string {
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

	switch strings.ToLower(udpProxyMode) {
	case "tcp":
		buf.WriteString(" --tcp")
	case "no":
	default:
		buf.WriteString(" --proxy")
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
	if connectTimeout != kDefaultConnectTimeout {
		buf.WriteString(" --connect-timeout ")
		buf.WriteString(strconv.Itoa(int(connectTimeout / time.Second)))
	}

	if udpPort := getExOptionConfig(args, "UdpPort"); udpPort != "" {
		ports := strings.FieldsFunc(udpPort, func(c rune) bool {
			return unicode.IsSpace(c) || c == ',' || c == '-'
		})
		if len(ports) == 1 {
			port, err := strconv.ParseUint(ports[0], 10, 16)
			if err != nil {
				warning("UdpPort %s is invalid: %v", udpPort, err)
			} else {
				buf.WriteString(fmt.Sprintf(" --port %d", port))
			}
		} else if len(ports) == 2 {
			func() {
				lowPort, err := strconv.ParseUint(ports[0], 10, 16)
				if err != nil {
					warning("UdpPort %s is invalid: %v", udpPort, err)
					return
				}
				highPort, err := strconv.ParseUint(ports[1], 10, 16)
				if err != nil {
					warning("UdpPort %s is invalid: %v", udpPort, err)
					return
				}
				buf.WriteString(fmt.Sprintf(" --port %d-%d", lowPort, highPort))
			}()
		} else {
			warning("UdpPort %s is invalid", udpPort)
		}
	}

	return buf.String()
}

func readFromStream(stream io.Reader) string {
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(stream)
	return strings.TrimSpace(buf.String())
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
			if args.Udp {
				warning("disable UDP since -oUdpMode=No")
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

	if args.Udp {
		return kUdpModeYes
	}
	return kUdpModeNo
}

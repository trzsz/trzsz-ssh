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
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/quic-go/quic-go"
	"github.com/trzsz/go-socks5"
	"github.com/trzsz/tsshd/tsshd"
	"golang.org/x/crypto/ssh"
)

type bindCfg struct {
	argument string
	addr     *string
	port     int
}

func (b *bindCfg) String() string {
	return b.argument
}

type forwardCfg struct {
	argument string
	bindAddr *string
	bindPort int
	destHost string
	destPort int
}

func (f *forwardCfg) String() string {
	return f.argument
}

var spaceRegexp = regexp.MustCompile(`\s+`)
var portOnlyRegexp = regexp.MustCompile(`^\d+$`)
var ipv6AndPortRegexp = regexp.MustCompile(`^\[([:\da-fA-F]+)\]:(\d+)$`)
var doubleIPv6Regexp = regexp.MustCompile(`^\[([:\da-fA-F]+)\]:(\d+):\[([:\da-fA-F]+)\]:(\d+)$`)
var firstIPv6Regexp = regexp.MustCompile(`^\[([:\da-fA-F]+)\]:(\d+):([^:]+):(\d+)$`)
var secondIPv6Regexp = regexp.MustCompile(`^([^:]+)?:(\d+):\[([:\da-fA-F]+)\]:(\d+)$`)
var middleIPv6Regexp = regexp.MustCompile(`^(\d+):\[([:\da-fA-F]+)\]:(\d+)$`)
var unixSocketRegexp = regexp.MustCompile(`^\/.+$`)

func parseBindCfg(s string) (*bindCfg, error) {
	s = strings.TrimSpace(s)

	if spaceRegexp.MatchString(s) {
		return nil, fmt.Errorf("invalid bind specification: %s", s)
	}

	newBindArg := func(addr *string, port string) (*bindCfg, error) {
		p, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid bind specification [%s]: %v", s, err)
		}
		return &bindCfg{s, addr, int(p)}, nil
	}

	if portOnlyRegexp.MatchString(s) {
		return newBindArg(nil, s)
	}

	tokens := strings.Split(s, "/")
	if len(tokens) == 2 && portOnlyRegexp.MatchString(tokens[1]) {
		return newBindArg(&tokens[0], tokens[1])
	}

	match := ipv6AndPortRegexp.FindStringSubmatch(s)
	if len(match) == 3 {
		return newBindArg(&match[1], match[2])
	}

	tokens = strings.Split(s, ":")
	if len(tokens) == 2 && portOnlyRegexp.MatchString(tokens[1]) {
		return newBindArg(&tokens[0], tokens[1])
	}

	if unixSocketRegexp.MatchString(s) {
		return &bindCfg{s, &s, -1}, nil
	}

	return nil, fmt.Errorf("invalid bind specification: %s", s)
}

func parseForwardCfg(s string) (*forwardCfg, error) {
	s = strings.TrimSpace(s)

	tokens := strings.Fields(s)
	if len(tokens) != 2 {
		return nil, fmt.Errorf("invalid forwarding config: %s", s)
	}

	bindCfg, err := parseBindCfg(tokens[0])
	if err != nil {
		return nil, fmt.Errorf("invalid forwarding config: %s", s)
	}

	newForwardCfg := func(host string, port string) (*forwardCfg, error) {
		dPort, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid forwarding config [%s]: %v", s, err)
		}
		return &forwardCfg{s, bindCfg.addr, bindCfg.port, host, int(dPort)}, nil
	}

	dest := tokens[1]
	tokens = strings.Split(dest, "/")
	if len(tokens) == 2 && portOnlyRegexp.MatchString(tokens[1]) {
		return newForwardCfg(tokens[0], tokens[1])
	}

	match := ipv6AndPortRegexp.FindStringSubmatch(dest)
	if len(match) == 3 {
		return newForwardCfg(match[1], match[2])
	}

	tokens = strings.Split(dest, ":")
	if len(tokens) == 2 && portOnlyRegexp.MatchString(tokens[1]) {
		return newForwardCfg(tokens[0], tokens[1])
	}

	if unixSocketRegexp.MatchString(dest) {
		return &forwardCfg{s, bindCfg.addr, bindCfg.port, dest, -1}, nil
	}

	return nil, fmt.Errorf("invalid forwarding config: %s", s)
}

func parseForwardArg(s string) (*forwardCfg, error) {
	s = strings.TrimSpace(s)

	if spaceRegexp.MatchString(s) {
		return nil, fmt.Errorf("invalid forwarding specification: %s", s)
	}

	newForwardCfg := func(bindAddr *string, bindPort *string, destHost string, destPort *string) (*forwardCfg, error) {
		bPort, dPort := -1, -1
		if bindPort != nil {
			v, err := strconv.ParseUint(*bindPort, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid forwarding specification [%s]: %v", s, err)
			}
			bPort = int(v)
		}
		if destPort != nil {
			v, err := strconv.ParseUint(*destPort, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid forwarding specification [%s]: %v", s, err)
			}
			dPort = int(v)
		}
		return &forwardCfg{s, bindAddr, int(bPort), destHost, int(dPort)}, nil
	}

	tokens := strings.Split(s, "/")
	if len(tokens) == 3 && portOnlyRegexp.MatchString(tokens[0]) && portOnlyRegexp.MatchString(tokens[2]) {
		return newForwardCfg(nil, &tokens[0], tokens[1], &tokens[2])
	}
	if len(tokens) == 4 && portOnlyRegexp.MatchString(tokens[1]) && portOnlyRegexp.MatchString(tokens[3]) {
		return newForwardCfg(&tokens[0], &tokens[1], tokens[2], &tokens[3])
	}

	match := doubleIPv6Regexp.FindStringSubmatch(s)
	if len(match) == 5 {
		return newForwardCfg(&match[1], &match[2], match[3], &match[4])
	}
	match = firstIPv6Regexp.FindStringSubmatch(s)
	if len(match) == 5 {
		return newForwardCfg(&match[1], &match[2], match[3], &match[4])
	}
	match = secondIPv6Regexp.FindStringSubmatch(s)
	if len(match) == 5 {
		return newForwardCfg(&match[1], &match[2], match[3], &match[4])
	}
	match = middleIPv6Regexp.FindStringSubmatch(s)
	if len(match) == 4 {
		return newForwardCfg(nil, &match[1], match[2], &match[3])
	}

	tokens = strings.Split(s, ":")
	if len(tokens) == 3 && portOnlyRegexp.MatchString(tokens[0]) && portOnlyRegexp.MatchString(tokens[2]) {
		return newForwardCfg(nil, &tokens[0], tokens[1], &tokens[2])
	}
	if len(tokens) == 4 && portOnlyRegexp.MatchString(tokens[1]) && portOnlyRegexp.MatchString(tokens[3]) {
		return newForwardCfg(&tokens[0], &tokens[1], tokens[2], &tokens[3])
	}

	if len(tokens) == 2 && portOnlyRegexp.MatchString(tokens[0]) && unixSocketRegexp.MatchString(tokens[1]) {
		return newForwardCfg(nil, &tokens[0], tokens[1], nil)
	}
	if len(tokens) == 3 && portOnlyRegexp.MatchString(tokens[1]) && unixSocketRegexp.MatchString(tokens[2]) {
		return newForwardCfg(&tokens[0], &tokens[1], tokens[2], nil)
	}
	if len(tokens) == 3 && portOnlyRegexp.MatchString(tokens[2]) && unixSocketRegexp.MatchString(tokens[0]) {
		return newForwardCfg(&tokens[0], nil, tokens[1], &tokens[2])
	}
	if len(tokens) == 2 && unixSocketRegexp.MatchString(tokens[0]) && unixSocketRegexp.MatchString(tokens[1]) {
		return newForwardCfg(&tokens[0], nil, tokens[1], nil)
	}

	return nil, fmt.Errorf("invalid forwarding specification: %s", s)
}

func isGatewayPorts(args *sshArgs) bool {
	return args.Gateway || strings.ToLower(getConfig(args.Destination, "GatewayPorts")) == "yes"
}

func isClosedError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) {
		return true
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	if errors.Is(err, io.ErrClosedPipe) {
		return true
	}
	var qse *quic.StreamError
	if errors.As(err, &qse) && qse.ErrorCode == 0 {
		return true
	}
	if strings.Contains(err.Error(), "io: read/write on closed pipe") {
		return true
	}
	return false
}

func forwardDeniedReason(err error, network string) string {
	if e, ok := err.(*tsshd.Error); ok && e.Code == tsshd.ErrProhibited {
		return e.Msg
	}

	buildDeniedMsg := func() string {
		option := "AllowTcpForwarding"
		if network == "unix" {
			option += ", AllowStreamLocalForwarding"
		}
		return fmt.Sprintf("Check [%s, DisableForwarding] in [/etc/ssh/sshd_config] on the server.", option)
	}

	if e, ok := err.(*ssh.OpenChannelError); ok && e.Reason == ssh.Prohibited {
		return buildDeniedMsg()
	}

	const kDeniedError = "request denied by peer"
	if err != nil && strings.Contains(err.Error(), kDeniedError) {
		return buildDeniedMsg() + " And check if the bind address is already in use."
	}

	return ""
}

func listenOnLocal(args *sshArgs, addr *string, port, name string) (listeners []net.Listener) {
	listen := func(network, address string) {
		listener, err := net.Listen(network, address)
		if err != nil {
			warning("%s listen on local [%s] [%s] failed: %v", name, network, address, err)
		} else {
			debug("%s listen on local [%s] [%s] success", name, network, address)
			listeners = append(listeners, listener)
			addOnCloseFunc(func() { _ = listener.Close() })
		}
	}
	if addr == nil && isGatewayPorts(args) || addr != nil && (*addr == "" || *addr == "*") {
		listen("tcp4", joinHostPort("0.0.0.0", port))
		listen("tcp6", joinHostPort("::", port))
		return
	}
	if addr == nil {
		listen("tcp4", joinHostPort("127.0.0.1", port))
		listen("tcp6", joinHostPort("::1", port))
		return
	}
	if strings.HasPrefix(*addr, "/") && port == "-1" {
		listen("unix", *addr)
		return
	}
	listen("tcp", joinHostPort(*addr, port))
	return
}

func listenOnRemote(args *sshArgs, client SshClient, f *forwardCfg) (listeners []net.Listener) {
	addr, port := f.bindAddr, strconv.Itoa(f.bindPort)
	listen := func(network, address string) {
		listener, err := client.Listen(network, address)
		if err != nil {
			if network == "tcp6" {
				debug("remote forwarding [%v] listen on remote [%s] [%s] failed: %v", f, network, address, err)
			} else if reason := forwardDeniedReason(err, network); reason != "" {
				warning("The remote forwarding [%v] was denied. %s", f, reason)
			} else {
				warning("remote forwarding [%v] listen on remote [%s] [%s] failed: %v", f, network, address, err)
			}
		} else {
			debug("remote forwarding [%v] listen on remote [%s] [%s] success", f, network, address)
			listeners = append(listeners, listener)
			addOnCloseFunc(func() { _ = listener.Close() })
		}
	}
	if addr == nil && isGatewayPorts(args) || addr != nil && (*addr == "" || *addr == "*") {
		listen("tcp4", joinHostPort("0.0.0.0", port))
		listen("tcp6", joinHostPort("::", port))
		return
	}
	if addr == nil {
		listen("tcp4", joinHostPort("127.0.0.1", port))
		listen("tcp6", joinHostPort("::1", port))
		return
	}
	if strings.HasPrefix(*addr, "/") && port == "-1" {
		listen("unix", *addr)
		return
	}
	listen("tcp", joinHostPort(*addr, port))
	return
}

func stdioForward(args *sshArgs, client SshClient, addr string) error {
	conn, err := client.DialTimeout("tcp", addr, getConnectTimeout(args))
	if err != nil {
		return fmt.Errorf("stdio forwarding [%s] failed: %v", addr, err)
	}

	var wg sync.WaitGroup

	wg.Go(func() {
		_, _ = io.Copy(conn, os.Stdin)

		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	})

	wg.Go(func() {
		_, _ = io.Copy(os.Stdout, conn)

		if cr, ok := conn.(interface{ CloseRead() error }); ok {
			_ = cr.CloseRead()
		}
	})

	wg.Wait()
	_ = conn.Close()
	_ = os.Stdout.Close()
	return nil
}

type sshResolver struct{}

func (d sshResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	return ctx, []byte{}, nil
}

func dynamicForward(client SshClient, b *bindCfg, args *sshArgs) {
	var dialError = errors.New("DIAL_ERROR_" + uuid.NewString())
	server, err := socks5.New(&socks5.Config{
		Resolver: &sshResolver{},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := client.DialTimeout(network, addr, getConnectTimeout(args))
			if err != nil {
				if reason := forwardDeniedReason(err, network); reason != "" {
					warning("The dynamic forwarding [%v] was denied. %s", b, reason)
				} else {
					warning("dynamic forwarding [%v] dial [%s] [%s] failed: %v", b, network, addr, err)
				}
				err = dialError
			}
			return conn, err
		},
		Logger: log.New(io.Discard, "", log.LstdFlags),
	})
	if err != nil {
		warning("dynamic forwarding [%v] failed: %v", b, err)
		return
	}

	name := fmt.Sprintf("dynamic forwarding [%v]", b)
	for _, listener := range listenOnLocal(args, b.addr, strconv.Itoa(b.port), name) {
		go func(listener net.Listener) {
			defer func() { _ = listener.Close() }()
			for {
				conn, err := listener.Accept()
				if err != nil {
					if isClosedError(err) {
						debug("dynamic forwarding [%v] closed: %v", b, err)
						break
					}
					warning("dynamic forwarding [%v] accept failed: %v", b, err)
					break
				}
				go func() {
					if err := server.ServeConn(conn); err != nil {
						if !enableDebugLogging {
							return
						}
						if isClosedError(err) {
							return
						}
						errMsg := err.Error()
						if strings.HasPrefix(errMsg, "Failed to handle request: ") {
							if strings.Contains(errMsg, dialError.Error()) {
								return
							}
							if strings.HasSuffix(errMsg, " write: broken pipe") {
								return
							}
							if strings.Contains(errMsg, " Application error 0x0 ") {
								return
							}
						}
						debug("dynamic forwarding [%v] serve failed: %v", b, err)
					}
				}()
			}
		}(listener)
	}
}

func netForward(local, remote net.Conn) {
	var wg sync.WaitGroup

	wg.Go(func() {
		_, _ = io.Copy(local, remote) // local <- remote

		if cw, ok := local.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}

		if cr, ok := remote.(interface{ CloseRead() error }); ok {
			_ = cr.CloseRead()
		}
	})

	wg.Go(func() {
		_, _ = io.Copy(remote, local) // remote <- local

		if cw, ok := remote.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}

		if cr, ok := local.(interface{ CloseRead() error }); ok {
			_ = cr.CloseRead()
		}
	})

	wg.Wait()
	_ = local.Close()
	_ = remote.Close()
}

func localForward(client SshClient, f *forwardCfg, args *sshArgs) {
	var network, remoteAddr string
	if f.destPort == -1 && strings.HasPrefix(f.destHost, "/") {
		network = "unix"
		remoteAddr = f.destHost
	} else {
		network = "tcp"
		remoteAddr = joinHostPort(f.destHost, strconv.Itoa(f.destPort))
	}
	timeout := getConnectTimeout(args)
	name := fmt.Sprintf("local forwarding [%v]", f)
	for _, listener := range listenOnLocal(args, f.bindAddr, strconv.Itoa(f.bindPort), name) {
		go func(listener net.Listener) {
			defer func() { _ = listener.Close() }()
			for {
				local, err := listener.Accept()
				if err != nil {
					if isClosedError(err) {
						debug("local forwarding [%v] closed: %v", f, err)
						break
					}
					warning("local forwarding [%v] accept failed: %v", f, err)
					break
				}
				remote, err := client.DialTimeout(network, remoteAddr, timeout)
				if err != nil {
					if reason := forwardDeniedReason(err, network); reason != "" {
						warning("The local forwarding [%v] was denied. %s", f, reason)
					} else {
						warning("local forwarding [%v] dial [%s] [%s] failed: %v", f, network, remoteAddr, err)
					}
					_ = local.Close()
					continue
				}
				go netForward(local, remote)
			}
		}(listener)
	}
}

func remoteForward(client SshClient, f *forwardCfg, args *sshArgs) {
	var network, localAddr string
	if f.destPort == -1 && strings.HasPrefix(f.destHost, "/") {
		network = "unix"
		localAddr = f.destHost
	} else {
		network = "tcp"
		localAddr = joinHostPort(f.destHost, strconv.Itoa(f.destPort))
	}
	timeout := getConnectTimeout(args)
	for _, listener := range listenOnRemote(args, client, f) {
		go func(listener net.Listener) {
			defer func() { _ = listener.Close() }()
			for {
				remote, err := listener.Accept()
				if err != nil {
					if isClosedError(err) {
						debug("remote forwarding [%v] closed: %v", f, err)
						break
					}
					warning("remote forwarding [%v] accept failed: %v", f, err)
					break
				}
				local, err := net.DialTimeout(network, localAddr, timeout)
				if err != nil {
					warning("remote forwarding [%v] dial [%s] [%s] failed: %v", f, network, localAddr, err)
					_ = remote.Close()
					continue
				}
				go netForward(local, remote)
			}
		}(listener)
	}
}

func sshPortForward(sshConn *sshConnection) {
	args := sshConn.param.args
	// clear all forwardings
	if strings.ToLower(getOptionConfig(args, "ClearAllForwardings")) == "yes" {
		debug("clear all forwardings")
		return
	}

	// dynamic forward
	for _, b := range args.DynamicForward.binds {
		dynamicForward(sshConn.client, b, args)
	}
	for _, s := range getAllOptionConfig(args, "DynamicForward") {
		b, err := parseBindCfg(s)
		if err != nil {
			warning("parse dynamic forwarding failed: %v", err)
			continue
		}
		dynamicForward(sshConn.client, b, args)
	}

	// local forward
	for _, f := range args.LocalForward.cfgs {
		localForward(sshConn.client, f, args)
	}
	for _, s := range getAllOptionConfig(args, "LocalForward") {
		es, err := expandTokens(s, sshConn.param, "%CdhijkLlnpru")
		if err != nil {
			warning("expand LocalForward [%s] failed: %v", s, err)
			continue
		}
		f, err := parseForwardCfg(es)
		if err != nil {
			warning("parse local forwarding failed: %v", err)
			continue
		}
		localForward(sshConn.client, f, args)
	}

	// remote forward
	for _, f := range args.RemoteForward.cfgs {
		remoteForward(sshConn.client, f, args)
	}
	for _, s := range getAllOptionConfig(args, "RemoteForward") {
		es, err := expandTokens(s, sshConn.param, "%CdhijkLlnpru")
		if err != nil {
			warning("expand RemoteForward [%s] failed: %v", s, err)
			continue
		}
		f, err := parseForwardCfg(es)
		if err != nil {
			warning("parse remote forwarding failed: %v", err)
			continue
		}
		remoteForward(sshConn.client, f, args)
	}
}

type x11Request struct {
	SingleConnection bool
	AuthProtocol     string
	AuthCookie       string
	ScreenNumber     uint32
}

func sshX11Forward(sshConn *sshConnection) {
	args := sshConn.param.args
	if args.NoX11Forward || !args.X11Untrusted && !args.X11Trusted && strings.ToLower(getOptionConfig(args, "ForwardX11")) != "yes" {
		return
	}

	display := os.Getenv("DISPLAY")
	if display == "" {
		warning("X11 forwarding is not working since environment variable DISPLAY is not set")
		return
	}
	hostname, displayNumber, err := resolveDisplayEnv(display)
	if err != nil {
		warning("X11 forwarding is not working due to: %v", err)
		return
	}

	var trusted bool
	if !args.X11Untrusted && (args.X11Trusted || strings.ToLower(getOptionConfig(args, "ForwardX11Trusted")) == "yes") {
		trusted = true
	}

	timeout := 1200
	if !trusted {
		forwardX11Timeout := getOptionConfig(args, "ForwardX11Timeout")
		if forwardX11Timeout != "" && strings.ToLower(forwardX11Timeout) != "none" {
			seconds, err := convertSshTime(forwardX11Timeout)
			if err != nil {
				warning("invalid ForwardX11Timeout '%s': %v", forwardX11Timeout, err)
			} else {
				timeout = seconds
			}
		}
	}

	cookie, proto, err := getXauthAndProto(display, trusted, timeout)
	if err != nil {
		warning("X11 forwarding get xauth failed: %v", err)
		return
	}

	payload := x11Request{
		SingleConnection: false,
		AuthProtocol:     proto,
		AuthCookie:       cookie,
		ScreenNumber:     0,
	}
	ok, err := sshConn.session.SendRequest(kX11RequestName, true, ssh.Marshal(payload))
	if err != nil {
		warning("X11 forwarding request failed: %v", err)
		return
	}
	if !ok {
		warning("The X11 forwarding request was denied. Check [X11Forwarding, X11DisplayOffset, DisableForwarding] in [/etc/ssh/sshd_config] on the server.")
		return
	}

	channels := sshConn.client.HandleChannelOpen(kX11ChannelType)
	if channels == nil {
		warning("already have handler for %s", kX11ChannelType)
		return
	}

	if sshConn.param.udpMode == kUdpModeNo {
		debug("request ssh X11 forwarding success")
	}

	go func() {
		for ch := range channels {
			channel, reqs, err := ch.Accept()
			if err != nil {
				warning("X11 forwarding accept failed: %v", err)
				continue
			}
			go ssh.DiscardRequests(reqs)
			go func() {
				serveX11(display, hostname, displayNumber, channel)
				_ = channel.Close()
			}()
		}
	}()
}

func resolveDisplayEnv(display string) (string, int, error) {
	colon := strings.LastIndex(display, ":")
	if colon < 0 {
		return "", 0, fmt.Errorf("no colon in env DISPLAY [%s]", display)
	}
	hostname := display[:colon]
	number := display[colon+1:]
	dot := strings.Index(number, ".")
	if dot < 0 {
		dot = len(number)
	}
	displayNumber, err := strconv.ParseUint(number[:dot], 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("display number [%s] in env DISPLAY [%s] invalid: %v", number[:dot], display, err)
	}
	return hostname, int(displayNumber), nil
}

func convertSshTime(time string) (int, error) {
	total := 0
	seconds := 0
	for _, ch := range time {
		switch {
		case ch >= '0' && ch <= '9':
			seconds = seconds*10 + int(ch-'0')
		case ch == 's' || ch == 'S':
			total += seconds
			seconds = 0
		case ch == 'm' || ch == 'M':
			total += seconds * 60
			seconds = 0
		case ch == 'h' || ch == 'H':
			total += seconds * 60 * 60
			seconds = 0
		case ch == 'd' || ch == 'D':
			total += seconds * 60 * 60 * 24
			seconds = 0
		case ch == 'w' || ch == 'W':
			total += seconds * 60 * 60 * 24 * 7
			seconds = 0
		default:
			return 0, fmt.Errorf("invalid char '%c'", ch)
		}
	}
	return total + seconds, nil
}

func serveX11(display, hostname string, displayNumber int, channel ssh.Channel) {
	var err error
	var conn net.Conn
	if hostname != "" && !strings.HasPrefix(hostname, "/") {
		conn, err = net.DialTimeout("tcp", joinHostPort(hostname, strconv.Itoa(6000+displayNumber)), time.Second)
	} else if strings.HasPrefix(display, "/") {
		conn, err = net.DialTimeout("unix", display, time.Second)
	} else {
		conn, err = net.DialTimeout("unix", fmt.Sprintf("/tmp/.X11-unix/X%d", displayNumber), time.Second)
	}
	if err != nil {
		warning("X11 forwarding dial [%s] failed: %v", display, err)
		return
	}

	forwardChannel(channel, conn)
}

func forwardChannel(channel ssh.Channel, conn net.Conn) {
	var wg sync.WaitGroup

	wg.Go(func() {
		_, _ = io.Copy(conn, channel)

		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}

		if cr, ok := channel.(interface{ CloseRead() error }); ok {
			_ = cr.CloseRead()
		}
	})

	wg.Go(func() {
		_, _ = io.Copy(channel, conn)

		_ = channel.CloseWrite()

		if cr, ok := conn.(interface{ CloseRead() error }); ok {
			_ = cr.CloseRead()
		}
	})

	wg.Wait()
	_ = conn.Close()
	_ = channel.Close()
}

func subsystemForward(client SshClient, name string) error {
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("new session for subsystem [%s] failed: %v", name, err)
	}
	defer func() { _ = session.Close() }()
	serverIn, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe for subsystem [%s] failed: %v", name, err)
	}
	serverOut, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe for subsystem [%s] failed: %v", name, err)
	}
	serverErr, err := session.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe for subsystem [%s] failed: %v", name, err)
	}

	if err := session.RequestSubsystem(name); err != nil {
		return fmt.Errorf("request subsystem [%s] failed: %v", name, err)
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		_, _ = io.Copy(serverIn, os.Stdin)
		_ = serverIn.Close()
	})
	wg.Go(func() {
		_, _ = io.Copy(os.Stdout, serverOut)
		_ = os.Stdout.Close()
	})
	wg.Go(func() {
		_, _ = io.Copy(os.Stderr, serverErr)
		_ = os.Stderr.Close()
	})
	wg.Wait()
	return nil
}

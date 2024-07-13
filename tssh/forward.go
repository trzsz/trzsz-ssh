/*
MIT License

Copyright (c) 2023-2024 The Trzsz SSH Authors.

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

	"github.com/trzsz/go-socks5"
	"golang.org/x/crypto/ssh"
)

type bindCfg struct {
	argument string
	addr     *string
	port     int
}

type forwardCfg struct {
	argument string
	bindAddr *string
	bindPort int
	destHost string
	destPort int
}

type closeWriter interface {
	CloseWrite() error
}

var spaceRegexp = regexp.MustCompile(`\s+`)
var portOnlyRegexp = regexp.MustCompile(`^\d+$`)
var ipv6AndPortRegexp = regexp.MustCompile(`^\[([:\da-fA-F]+)\]:(\d+)$`)
var doubleIPv6Regexp = regexp.MustCompile(`^\[([:\da-fA-F]+)\]:(\d+):\[([:\da-fA-F]+)\]:(\d+)$`)
var firstIPv6Regexp = regexp.MustCompile(`^\[([:\da-fA-F]+)\]:(\d+):([^:]+):(\d+)$`)
var secondIPv6Regexp = regexp.MustCompile(`^([^:]+)?:(\d+):\[([:\da-fA-F]+)\]:(\d+)$`)
var middleIPv6Regexp = regexp.MustCompile(`^(\d+):\[([:\da-fA-F]+)\]:(\d+)$`)

func parseBindCfg(s string) (*bindCfg, error) {
	s = strings.TrimSpace(s)

	if spaceRegexp.MatchString(s) {
		return nil, fmt.Errorf("invalid bind specification: %s", s)
	}

	newBindArg := func(addr *string, port string) (*bindCfg, error) {
		p, err := strconv.Atoi(port)
		if err != nil {
			return nil, fmt.Errorf("invalid bind specification [%s]: %v", s, err)
		}
		return &bindCfg{s, addr, p}, nil
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

	return nil, fmt.Errorf("invalid bind specification: %s", s)
}

func parseForwardCfg(s string) (*forwardCfg, error) {
	s = strings.TrimSpace(s)

	tokens := strings.Fields(s)
	if len(tokens) != 2 {
		return nil, fmt.Errorf("invalid forward config: %s", s)
	}

	bindCfg, err := parseBindCfg(tokens[0])
	if err != nil {
		return nil, fmt.Errorf("invalid forward config: %s", s)
	}

	newForwardCfg := func(host string, port string) (*forwardCfg, error) {
		dPort, err := strconv.Atoi(port)
		if err != nil {
			return nil, fmt.Errorf("invalid forward config [%s]: %v", s, err)
		}
		return &forwardCfg{s, bindCfg.addr, bindCfg.port, host, dPort}, nil
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

	return nil, fmt.Errorf("invalid forward config: %s", s)
}

func parseForwardArg(s string) (*forwardCfg, error) {
	s = strings.TrimSpace(s)

	if spaceRegexp.MatchString(s) {
		return nil, fmt.Errorf("invalid forward specification: %s", s)
	}

	newForwardCfg := func(bindAddr *string, bindPort string, destHost string, destPort string) (*forwardCfg, error) {
		bPort, err := strconv.Atoi(bindPort)
		if err != nil {
			return nil, fmt.Errorf("invalid forward specification [%s]: %v", s, err)
		}
		dPort, err := strconv.Atoi(destPort)
		if err != nil {
			return nil, fmt.Errorf("invalid forward specification [%s]: %v", s, err)
		}
		return &forwardCfg{s, bindAddr, bPort, destHost, dPort}, nil
	}

	tokens := strings.Split(s, "/")
	if len(tokens) == 3 && portOnlyRegexp.MatchString(tokens[0]) && portOnlyRegexp.MatchString(tokens[2]) {
		return newForwardCfg(nil, tokens[0], tokens[1], tokens[2])
	}
	if len(tokens) == 4 && portOnlyRegexp.MatchString(tokens[1]) && portOnlyRegexp.MatchString(tokens[3]) {
		return newForwardCfg(&tokens[0], tokens[1], tokens[2], tokens[3])
	}

	match := doubleIPv6Regexp.FindStringSubmatch(s)
	if len(match) == 5 {
		return newForwardCfg(&match[1], match[2], match[3], match[4])
	}
	match = firstIPv6Regexp.FindStringSubmatch(s)
	if len(match) == 5 {
		return newForwardCfg(&match[1], match[2], match[3], match[4])
	}
	match = secondIPv6Regexp.FindStringSubmatch(s)
	if len(match) == 5 {
		return newForwardCfg(&match[1], match[2], match[3], match[4])
	}
	match = middleIPv6Regexp.FindStringSubmatch(s)
	if len(match) == 4 {
		return newForwardCfg(nil, match[1], match[2], match[3])
	}

	tokens = strings.Split(s, ":")
	if len(tokens) == 3 && portOnlyRegexp.MatchString(tokens[0]) && portOnlyRegexp.MatchString(tokens[2]) {
		return newForwardCfg(nil, tokens[0], tokens[1], tokens[2])
	}
	if len(tokens) == 4 && portOnlyRegexp.MatchString(tokens[1]) && portOnlyRegexp.MatchString(tokens[3]) {
		return newForwardCfg(&tokens[0], tokens[1], tokens[2], tokens[3])
	}

	return nil, fmt.Errorf("invalid forward specification: %s", s)
}

func isGatewayPorts(args *sshArgs) bool {
	return args.Gateway || strings.ToLower(getConfig(args.Destination, "GatewayPorts")) == "yes"
}

func listenOnLocal(args *sshArgs, addr *string, port string) (listeners []net.Listener) {
	listen := func(network, address string) {
		listener, err := net.Listen(network, address)
		if err != nil {
			debug("forward listen on local %s '%s' failed: %v", network, address, err)
		} else {
			debug("forward listen on local %s '%s' success", network, address)
			listeners = append(listeners, listener)
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
	listen("tcp", joinHostPort(*addr, port))
	return
}

func listenOnRemote(args *sshArgs, client SshClient, addr *string, port string) (listeners []net.Listener) {
	listen := func(network, address string) {
		listener, err := client.Listen(network, address)
		if err != nil {
			debug("forward listen on remote %s '%s' failed: %v", network, address, err)
		} else {
			debug("forward listen on remote %s '%s' success", network, address)
			listeners = append(listeners, listener)
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
	listen("tcp", joinHostPort(*addr, port))
	return
}

func stdioForward(client SshClient, addr string) (*sync.WaitGroup, error) {
	conn, err := client.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("stdio forward failed: %v", err)
	}
	defer conn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(conn, os.Stdin)
		done <- struct{}{}
		wg.Done()
	}()
	go func() {
		_, _ = io.Copy(os.Stdout, conn)
		done <- struct{}{}
		wg.Done()
	}()
	<-done

	return &wg, nil
}

type sshResolver struct{}

func (d sshResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	return ctx, []byte{}, nil
}

func dynamicForward(client SshClient, b *bindCfg, args *sshArgs) {
	server, err := socks5.New(&socks5.Config{
		Resolver: &sshResolver{},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return client.DialTimeout(network, addr, 10*time.Second)
		},
		Logger: log.New(io.Discard, "", log.LstdFlags),
	})
	if err != nil {
		warning("dynamic forward failed: %v", err)
		return
	}

	for _, listener := range listenOnLocal(args, b.addr, strconv.Itoa(b.port)) {
		go func(listener net.Listener) {
			defer listener.Close()
			for {
				conn, err := listener.Accept()
				if err == io.EOF {
					break
				}
				if err != nil {
					debug("dynamic forward accept failed: %v", err)
					continue
				}
				go func() {
					if err := server.ServeConn(conn); err != nil {
						debug("dynamic forward serve failed: %v", err)
					}
				}()
			}
		}(listener)
	}
}

func netForward(local, remote net.Conn) {
	defer local.Close()
	defer remote.Close()

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(local, remote)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(remote, local)
		done <- struct{}{}
	}()
	<-done
}

func localForward(client SshClient, f *forwardCfg, args *sshArgs) {
	remoteAddr := joinHostPort(f.destHost, strconv.Itoa(f.destPort))
	for _, listener := range listenOnLocal(args, f.bindAddr, strconv.Itoa(f.bindPort)) {
		go func(listener net.Listener) {
			defer listener.Close()
			for {
				local, err := listener.Accept()
				if err == io.EOF {
					break
				}
				if err != nil {
					debug("local forward accept failed: %v", err)
					continue
				}
				remote, err := client.DialTimeout("tcp", remoteAddr, 10*time.Second)
				if err != nil {
					debug("local forward dial [%s] failed: %v", remoteAddr, err)
					local.Close()
					continue
				}
				go netForward(local, remote)
			}
		}(listener)
	}
}

func remoteForward(client SshClient, f *forwardCfg, args *sshArgs) {
	localAddr := joinHostPort(f.destHost, strconv.Itoa(f.destPort))
	for _, listener := range listenOnRemote(args, client, f.bindAddr, strconv.Itoa(f.bindPort)) {
		go func(listener net.Listener) {
			defer listener.Close()
			for {
				remote, err := listener.Accept()
				if err == io.EOF {
					break
				}
				if err != nil {
					debug("remote forward accept failed: %v", err)
					continue
				}
				local, err := net.DialTimeout("tcp", localAddr, 10*time.Second)
				if err != nil {
					debug("remote forward dial [%s] failed: %v", localAddr, err)
					remote.Close()
					continue
				}
				go netForward(local, remote)
			}
		}(listener)
	}
}

func sshForward(client SshClient, args *sshArgs, param *sshParam) error {
	// clear all forwardings
	if strings.ToLower(getOptionConfig(args, "ClearAllForwardings")) == "yes" {
		return nil
	}

	// dynamic forward
	for _, b := range args.DynamicForward.binds {
		dynamicForward(client, b, args)
	}
	for _, s := range getAllOptionConfig(args, "DynamicForward") {
		b, err := parseBindCfg(s)
		if err != nil {
			warning("dynamic forward failed: %v", err)
			continue
		}
		dynamicForward(client, b, args)
	}

	// local forward
	for _, f := range args.LocalForward.cfgs {
		localForward(client, f, args)
	}
	for _, s := range getAllOptionConfig(args, "LocalForward") {
		es, err := expandTokens(s, args, param, "%CdhijkLlnpru")
		if err != nil {
			warning("expand LocalForward [%s] failed: %v", s, err)
			continue
		}
		f, err := parseForwardCfg(es)
		if err != nil {
			warning("local forward failed: %v", err)
			continue
		}
		localForward(client, f, args)
	}

	// remote forward
	for _, f := range args.RemoteForward.cfgs {
		remoteForward(client, f, args)
	}
	for _, s := range getAllOptionConfig(args, "RemoteForward") {
		es, err := expandTokens(s, args, param, "%CdhijkLlnpru")
		if err != nil {
			warning("expand RemoteForward [%s] failed: %v", s, err)
			continue
		}
		f, err := parseForwardCfg(es)
		if err != nil {
			warning("remote forward failed: %v", err)
			continue
		}
		remoteForward(client, f, args)
	}

	return nil
}

type x11Request struct {
	SingleConnection bool
	AuthProtocol     string
	AuthCookie       string
	ScreenNumber     uint32
}

func sshX11Forward(args *sshArgs, client SshClient, session SshSession) {
	if args.NoX11Forward || !args.X11Untrusted && !args.X11Trusted && strings.ToLower(getOptionConfig(args, "ForwardX11")) != "yes" {
		return
	}

	display := os.Getenv("DISPLAY")
	if display == "" {
		warning("X11 forwarding is not working since environment variable DISPLAY is not set")
		return
	}
	hostname, displayNumber := resolveDisplayEnv(display)

	trusted := false
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
	ok, err := session.SendRequest(kX11RequestName, true, ssh.Marshal(payload))
	if err != nil {
		warning("X11 forwarding request failed: %v", err)
		return
	}
	if !ok {
		warning("X11 forwarding request denied")
		return
	}

	channels := client.HandleChannelOpen(kX11ChannelType)
	if channels == nil {
		warning("already have handler for %s", kX11ChannelType)
		return
	}
	go func() {
		for ch := range channels {
			channel, reqs, err := ch.Accept()
			if err != nil {
				continue
			}
			go ssh.DiscardRequests(reqs)
			go func() {
				serveX11(display, hostname, displayNumber, channel)
				channel.Close()
			}()
		}
	}()
}

func resolveDisplayEnv(display string) (string, int) {
	colon := strings.LastIndex(display, ":")
	if colon < 0 {
		return "", 0
	}
	hostname := display[:colon]
	display = display[colon+1:]
	dot := strings.Index(display, ".")
	if dot < 0 {
		dot = len(display)
	}
	displayNumber, err := strconv.Atoi(display[:dot])
	if err != nil {
		return "", 0
	}
	return hostname, displayNumber
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
		debug("X11 forwarding dial [%s] failed: %v", display, err)
		return
	}

	forwardChannel(channel, conn)
}

func forwardChannel(channel ssh.Channel, conn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		_, _ = io.Copy(conn, channel)
		if cw, ok := conn.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			// close the entire stream since there is no half-close
			time.Sleep(200 * time.Millisecond)
			_ = conn.Close()
		}
		wg.Done()
	}()
	go func() {
		_, _ = io.Copy(channel, conn)
		_ = channel.CloseWrite()
		wg.Done()
	}()

	wg.Wait()
	conn.Close()
	channel.Close()
}

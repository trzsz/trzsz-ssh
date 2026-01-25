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
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
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
	udp      bool
	argument string
	bindAddr *string
	bindPort int
	destHost string
	destPort int
}

func (f *forwardCfg) String() string {
	return f.argument
}

var portOnlyRegexp = regexp.MustCompile(`^\d+$`)
var ipv6AndPortRegexp = regexp.MustCompile(`^\[([:\da-fA-F]+)\]:(\d+)$`)
var doubleIPv6Regexp = regexp.MustCompile(`^\[([:\da-fA-F]+)\]:(\d+):\[([:\da-fA-F]+)\]:(\d+)$`)
var firstIPv6Regexp = regexp.MustCompile(`^\[([:\da-fA-F]+)\]:(\d+):([^:]+):(\d+)$`)
var secondIPv6Regexp = regexp.MustCompile(`^([^:]+)?:(\d+):\[([:\da-fA-F]+)\]:(\d+)$`)
var middleIPv6Regexp = regexp.MustCompile(`^(\d+):\[([:\da-fA-F]+)\]:(\d+)$`)
var unixSocketRegexp = regexp.MustCompile(`^\/.+$`)

func parseBindCfg(str string) (*bindCfg, error) {
	str = strings.TrimSpace(str)

	newBindArg := func(addr *string, port string) (*bindCfg, error) {
		p, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid bind specification [%s]: %v", str, err)
		}
		return &bindCfg{str, addr, int(p)}, nil
	}

	if portOnlyRegexp.MatchString(str) {
		return newBindArg(nil, str)
	}

	tokens := strings.Split(str, "/")
	if len(tokens) == 2 && portOnlyRegexp.MatchString(tokens[1]) {
		return newBindArg(&tokens[0], tokens[1])
	}

	match := ipv6AndPortRegexp.FindStringSubmatch(str)
	if len(match) == 3 {
		return newBindArg(&match[1], match[2])
	}

	tokens = strings.Split(str, ":")
	if len(tokens) == 2 && portOnlyRegexp.MatchString(tokens[1]) {
		return newBindArg(&tokens[0], tokens[1])
	}

	if unixSocketRegexp.MatchString(str) {
		return &bindCfg{str, &str, -1}, nil
	}

	return nil, fmt.Errorf("invalid bind specification: %s", str)
}

func parseForwardCfg(param *sshParam, udp bool, str string) (*forwardCfg, error) {
	expandedStr, err := expandTokens(str, param, "%CdhijkLlnpru")
	if err != nil {
		return nil, fmt.Errorf("expand forwarding config [%s] failed: %v", str, err)
	}

	tokens := strings.Fields(expandedStr)
	if len(tokens) != 2 {
		return nil, fmt.Errorf("invalid forwarding config: %s", str)
	}

	bindCfg, err := parseBindCfg(tokens[0])
	if err != nil {
		return nil, fmt.Errorf("invalid forwarding config: %s", str)
	}

	newForwardCfg := func(host string, port string) (*forwardCfg, error) {
		dPort, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid forwarding config [%s]: %v", str, err)
		}
		return &forwardCfg{udp, str, bindCfg.addr, bindCfg.port, host, int(dPort)}, nil
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
		return &forwardCfg{udp, str, bindCfg.addr, bindCfg.port, dest, -1}, nil
	}

	return nil, fmt.Errorf("invalid forwarding config: %s", str)
}

func isUdpPrefix(str string) bool {
	if len(str) < 4 {
		return false
	}
	if str[0] != 'u' && str[0] != 'U' {
		return false
	}
	if str[1] != 'd' && str[1] != 'D' {
		return false
	}
	if str[2] != 'p' && str[2] != 'P' {
		return false
	}
	return str[3] == '/' || str[3] == ':' || str[3] == '-' || str[3] == '_'
}

func parseForwardArg(str string) (*forwardCfg, error) {
	str = strings.TrimSpace(str)

	udp := isUdpPrefix(str)
	val := str
	if udp {
		val = str[4:]
	}

	newForwardCfg := func(bindAddr *string, bindPort *string, destHost string, destPort *string) (*forwardCfg, error) {
		bPort, dPort := -1, -1
		if bindPort != nil {
			v, err := strconv.ParseUint(*bindPort, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid forwarding specification [%s]: %v", str, err)
			}
			bPort = int(v)
		}
		if destPort != nil {
			v, err := strconv.ParseUint(*destPort, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid forwarding specification [%s]: %v", str, err)
			}
			dPort = int(v)
		}
		return &forwardCfg{udp, str, bindAddr, int(bPort), destHost, int(dPort)}, nil
	}

	tokens := strings.Split(val, "/")
	if len(tokens) == 3 && portOnlyRegexp.MatchString(tokens[0]) && portOnlyRegexp.MatchString(tokens[2]) {
		return newForwardCfg(nil, &tokens[0], tokens[1], &tokens[2])
	}
	if len(tokens) == 4 && portOnlyRegexp.MatchString(tokens[1]) && portOnlyRegexp.MatchString(tokens[3]) {
		return newForwardCfg(&tokens[0], &tokens[1], tokens[2], &tokens[3])
	}

	match := doubleIPv6Regexp.FindStringSubmatch(val)
	if len(match) == 5 {
		return newForwardCfg(&match[1], &match[2], match[3], &match[4])
	}
	match = firstIPv6Regexp.FindStringSubmatch(val)
	if len(match) == 5 {
		return newForwardCfg(&match[1], &match[2], match[3], &match[4])
	}
	match = secondIPv6Regexp.FindStringSubmatch(val)
	if len(match) == 5 {
		return newForwardCfg(&match[1], &match[2], match[3], &match[4])
	}
	match = middleIPv6Regexp.FindStringSubmatch(val)
	if len(match) == 4 {
		return newForwardCfg(nil, &match[1], match[2], &match[3])
	}

	tokens = strings.Split(val, ":")
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

	return nil, fmt.Errorf("invalid forwarding specification: %s", str)
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

func localForward(sshConn *sshConnection, f *forwardCfg, gateway bool, timeout time.Duration) {
	if f.udp {
		localForwardUDP(sshConn, f, gateway, timeout)
	} else {
		localForwardTCP(sshConn, f, gateway, timeout)
	}
}

func remoteForward(sshConn *sshConnection, f *forwardCfg, gateway bool, timeout time.Duration) {
	if f.udp {
		remoteForwardUDP(sshConn, f, gateway, timeout)
	} else {
		remoteForwardTCP(sshConn, f, gateway, timeout)
	}
}

func sshPortForward(sshConn *sshConnection) {
	args := sshConn.param.args
	// clear all forwardings
	if strings.ToLower(getOptionConfig(args, "ClearAllForwardings")) == "yes" {
		debug("clear all forwardings")
		return
	}

	warnedUDP := false
	warnRequiredUDP := func() {
		if warnedUDP {
			return
		}
		warnedUDP = true
		warning("UDP forwarding does not work because tssh is not running in UDP mode")
	}

	gateway := isGatewayPorts(sshConn.param.args)
	timeout := getConnectTimeout(sshConn.param.args)

	// dynamic forward
	for _, b := range args.DynamicForward.binds {
		dynamicForward(sshConn.client, b, gateway, timeout)
	}
	for _, s := range getAllOptionConfig(args, "DynamicForward") {
		b, err := parseBindCfg(s)
		if err != nil {
			warning("parse dynamic forwarding failed: %v", err)
			continue
		}
		dynamicForward(sshConn.client, b, gateway, timeout)
	}

	// local forward
	for _, f := range args.LocalForward.cfgs {
		if f.udp && sshConn.param.udpMode == kUdpModeNo {
			warnRequiredUDP()
			continue
		}
		localForward(sshConn, f, gateway, timeout)
	}
	for _, s := range getAllOptionConfig(args, "LocalForward") {
		f, err := parseForwardCfg(sshConn.param, false, s)
		if err != nil {
			warning("parse local forwarding failed: %v", err)
			continue
		}
		localForward(sshConn, f, gateway, timeout)
	}
	for _, s := range getAllOptionConfig(args, "UdpLocalForward") {
		if sshConn.param.udpMode == kUdpModeNo {
			warnRequiredUDP()
			break
		}
		f, err := parseForwardCfg(sshConn.param, true, s)
		if err != nil {
			warning("parse udp local forwarding failed: %v", err)
			continue
		}
		localForward(sshConn, f, gateway, timeout)
	}

	// remote forward
	for _, f := range args.RemoteForward.cfgs {
		if f.udp && sshConn.param.udpMode == kUdpModeNo {
			warnRequiredUDP()
			continue
		}
		remoteForward(sshConn, f, gateway, timeout)
	}
	for _, s := range getAllOptionConfig(args, "RemoteForward") {
		f, err := parseForwardCfg(sshConn.param, false, s)
		if err != nil {
			warning("parse remote forwarding failed: %v", err)
			continue
		}
		remoteForward(sshConn, f, gateway, timeout)
	}
	for _, s := range getAllOptionConfig(args, "UdpRemoteForward") {
		if sshConn.param.udpMode == kUdpModeNo {
			warnRequiredUDP()
			break
		}
		f, err := parseForwardCfg(sshConn.param, true, s)
		if err != nil {
			warning("parse udp local forwarding failed: %v", err)
			continue
		}
		remoteForward(sshConn, f, gateway, timeout)
	}
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

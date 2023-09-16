/*
MIT License

Copyright (c) 2023 Lonny Wong <lonnywong@qq.com>
Copyright (c) 2023 [Contributors](https://github.com/trzsz/trzsz-ssh/graphs/contributors)

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

	"github.com/armon/go-socks5"
	"golang.org/x/crypto/ssh"
)

type bindCfg struct {
	addr *string
	port int
}

type forwardCfg struct {
	bindAddr *string
	bindPort int
	destHost string
	destPort int
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
		return &bindCfg{addr, p}, nil
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
		return &forwardCfg{bindCfg.addr, bindCfg.port, host, dPort}, nil
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
		return &forwardCfg{bindAddr, bPort, destHost, dPort}, nil
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

func listenOnLocal(args *sshArgs, addr *string, port string) (listeners []net.Listener, errs []error) {
	listen := func(network, address string) {
		listener, err := net.Listen(network, address)
		if err != nil {
			errs = append(errs, fmt.Errorf("listen on '%s' failed: %v", address, err))
		} else {
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

func listenOnRemote(args *sshArgs, client *ssh.Client, addr *string, port string) (listeners []net.Listener, errs []error) {
	listen := func(network, address string) {
		listener, err := client.Listen(network, address)
		if err != nil {
			errs = append(errs, fmt.Errorf("listen on '%s' failed: %v", address, err))
		} else {
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

func stdioForward(client *ssh.Client, addr string) (*sync.WaitGroup, error) {
	conn, err := dialWithTimeout(client, "tcp", addr)
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

func dynamicForward(client *ssh.Client, b *bindCfg, args *sshArgs) {
	server, err := socks5.New(&socks5.Config{
		Resolver: &sshResolver{},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialWithTimeout(client, network, addr)
		},
		Logger: log.New(io.Discard, "", log.LstdFlags),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "dynamic forward failed: %v\r\n", err)
		return
	}

	listeners, errs := listenOnLocal(args, b.addr, strconv.Itoa(b.port))
	for _, err := range errs {
		fmt.Fprintf(os.Stderr, "dynamic forward listen failed: %v\r\n", err)
	}
	for _, listener := range listeners {
		go func(listener net.Listener) {
			if err := server.Serve(listener); err != nil {
				fmt.Fprintf(os.Stderr, "dynamic forward serve failed: %v\r\n", err)
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

func localForward(client *ssh.Client, f *forwardCfg, args *sshArgs) {
	listeners, errs := listenOnLocal(args, f.bindAddr, strconv.Itoa(f.bindPort))
	for _, err := range errs {
		fmt.Fprintf(os.Stderr, "local forward listen failed: %v\r\n", err)
	}
	remoteAddr := joinHostPort(f.destHost, strconv.Itoa(f.destPort))
	for _, listener := range listeners {
		go func(listener net.Listener) {
			defer listener.Close()
			for {
				local, err := listener.Accept()
				if err == io.EOF {
					break
				}
				if err != nil {
					fmt.Fprintf(os.Stderr, "local forward accept failed: %v\r\n", err)
					continue
				}
				remote, err := dialWithTimeout(client, "tcp", remoteAddr)
				if err != nil {
					fmt.Fprintf(os.Stderr, "local forward dial [%s] failed: %v\r\n", remoteAddr, err)
					local.Close()
					continue
				}
				go netForward(local, remote)
			}
		}(listener)
	}
}

func remoteForward(client *ssh.Client, f *forwardCfg, args *sshArgs) {
	listeners, errs := listenOnRemote(args, client, f.bindAddr, strconv.Itoa(f.bindPort))
	for _, err := range errs {
		fmt.Fprintf(os.Stderr, "remote forward listen failed: %v\r\n", err)
	}
	localAddr := joinHostPort(f.destHost, strconv.Itoa(f.destPort))
	for _, listener := range listeners {
		go func(listener net.Listener) {
			defer listener.Close()
			for {
				remote, err := listener.Accept()
				if err == io.EOF {
					break
				}
				if err != nil {
					fmt.Fprintf(os.Stderr, "remote forward accept failed: %v\r\n", err)
					continue
				}
				local, err := net.DialTimeout("tcp", localAddr, 3*time.Second)
				if err != nil {
					fmt.Fprintf(os.Stderr, "remote forward dial [%s] failed: %v\r\n", localAddr, err)
					remote.Close()
					continue
				}
				go netForward(local, remote)
			}
		}(listener)
	}
}

func sshForward(client *ssh.Client, args *sshArgs) error {
	// dynamic forward
	for _, b := range args.DynamicForward.binds {
		dynamicForward(client, b, args)
	}
	for _, s := range getAllConfig(args.Destination, "DynamicForward") {
		b, err := parseBindCfg(s)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dynamic forward failed: %v\r\n", err)
			continue
		}
		dynamicForward(client, b, args)
	}

	// local forward
	for _, f := range args.LocalForward.cfgs {
		localForward(client, f, args)
	}
	for _, s := range getAllConfig(args.Destination, "LocalForward") {
		f, err := parseForwardCfg(s)
		if err != nil {
			fmt.Fprintf(os.Stderr, "local forward failed: %v\r\n", err)
			continue
		}
		localForward(client, f, args)
	}

	// remote forward
	for _, f := range args.RemoteForward.cfgs {
		remoteForward(client, f, args)
	}
	for _, s := range getAllConfig(args.Destination, "RemoteForward") {
		f, err := parseForwardCfg(s)
		if err != nil {
			fmt.Fprintf(os.Stderr, "remote forward failed: %v\r\n", err)
			continue
		}
		remoteForward(client, f, args)
	}

	return nil
}

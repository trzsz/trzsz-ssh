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
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const kWarnIntervalSeconds = 60
const kDefaultForwardUdpTimeout = 5 * time.Minute

var udpForwradTimeoutHandlerOnce sync.Once

var udpLocalForwarderMutex sync.Mutex
var udpLocalForwarderList []*udpLocalForwarder

var udpRemoteForwarderMutex sync.Mutex
var udpRemoteForwarderList []*udpRemoteForwarder

type udpForwardSession struct {
	remoteConn PacketConn
	lastActive atomic.Int64
}

type udpLocalForwarder struct {
	mutex       sync.Mutex
	client      SshClient
	timeout     time.Duration
	remoteNet   string
	remoteAddr  string
	localConn   net.PacketConn
	fwdConfig   *forwardCfg
	fwdSessions map[string]*udpForwardSession
	warnMutex   sync.Mutex
	lastWarn    map[string]int64
}

func (f *udpLocalForwarder) warning(format string, args ...any) {
	if !enableWarningLogging {
		return
	}

	key := format
	now := time.Now().Unix()

	f.warnMutex.Lock()
	if last, ok := f.lastWarn[key]; ok && now-last < kWarnIntervalSeconds {
		f.warnMutex.Unlock()
		debug(format, args...)
		return
	}
	f.lastWarn[key] = now
	f.warnMutex.Unlock()

	warning(format, args...)
}

func (f *udpLocalForwarder) run() {
	defer func() { _ = f.localConn.Close() }()

	udpLocalForwarderMutex.Lock()
	udpLocalForwarderList = append(udpLocalForwarderList, f)
	udpLocalForwarderMutex.Unlock()

	buf := make([]byte, 0xffff)
	for {
		n, addr, err := f.localConn.ReadFrom(buf)
		if err != nil {
			if isClosedError(err) {
				debug("udp local forwarding [%v] local closed: %v", f.fwdConfig, err)
				break
			}
			warning("udp local forwarding [%v] read failed: %v", f.fwdConfig, err)
			break
		}

		f.handlePacket(addr, buf[:n])
	}

	udpLocalForwarderMutex.Lock()
	for i, fwd := range udpLocalForwarderList {
		if fwd == f {
			udpLocalForwarderList[i] = udpLocalForwarderList[len(udpLocalForwarderList)-1]
			udpLocalForwarderList[len(udpLocalForwarderList)-1] = nil
			udpLocalForwarderList = udpLocalForwarderList[:len(udpLocalForwarderList)-1]
			break
		}
	}
	udpLocalForwarderMutex.Unlock()
}

func (f *udpLocalForwarder) handlePacket(clientAddr net.Addr, data []byte) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	clientKey := "nil"
	if clientAddr != nil {
		clientKey = clientAddr.String()
	}
	session, exists := f.fwdSessions[clientKey]

	if !exists {
		conn, err := f.client.DialUDP(f.remoteNet, f.remoteAddr, f.timeout)
		if err != nil {
			if reason := forwardDeniedReason(err, f.remoteNet); reason != "" {
				f.warning("The udp local forwarding [%v] was denied. %s", f.fwdConfig, reason)
			} else {
				f.warning("udp local forwarding [%v] dial [%s] [%s] failed: %v", f.fwdConfig, f.remoteNet, f.remoteAddr, err)
			}
			return
		}
		session = &udpForwardSession{remoteConn: conn}
		session.lastActive.Store(time.Now().Unix())
		f.fwdSessions[clientKey] = session

		clonedClientAddr := cloneNetAddr(clientAddr)
		go func() {
			defer func() {
				_ = session.remoteConn.Close()
				f.mutex.Lock()
				defer f.mutex.Unlock()
				delete(f.fwdSessions, clientKey)
			}()
			if err := conn.Consume(func(data []byte) error {
				session.lastActive.Store(time.Now().Unix())
				if _, err := f.localConn.WriteTo(data, clonedClientAddr); err != nil {
					f.warning("udp local forwarding [%v] write to [%s] failed: %v", f.fwdConfig, clientKey, err)
				}
				return nil
			}); err != nil {
				if isClosedError(err) {
					debug("udp local forwarding [%v] consume closed: %v", f.fwdConfig, err)
					return
				}
				f.warning("udp local forwarding [%v] consume failed: %v", f.fwdConfig, err)
			}
		}()
	}

	session.lastActive.Store(time.Now().Unix())

	if err := session.remoteConn.Write(data); err != nil {
		f.warning("udp local forwarding [%v] write failed: %v", f.fwdConfig, err)
		_ = session.remoteConn.Close()
		delete(f.fwdSessions, clientKey)
	}
}

func (f *udpLocalForwarder) cleanupTimeout(fwdExpireBefore, warnExpireBefore int64) {
	f.mutex.Lock()
	for key, session := range f.fwdSessions {
		if session.lastActive.Load() < fwdExpireBefore {
			_ = session.remoteConn.Close()
			delete(f.fwdSessions, key)
		}
	}
	f.mutex.Unlock()

	f.warnMutex.Lock()
	for key, unix := range f.lastWarn {
		if unix < warnExpireBefore {
			delete(f.lastWarn, key)
		}
	}
	f.warnMutex.Unlock()
}

type udpRemoteForwarder struct {
	localConn  io.ReadWriteCloser
	remoteConn PacketConn
	fwdConfig  *forwardCfg
	lastActive atomic.Int64
	closed     atomic.Bool
}

func (f *udpRemoteForwarder) Close() {
	if !f.closed.CompareAndSwap(false, true) {
		return
	}
	_ = f.localConn.Close()
	_ = f.remoteConn.Close()
}

func (f *udpRemoteForwarder) run() {
	defer f.Close()

	f.lastActive.Store(time.Now().Unix())

	udpRemoteForwarderMutex.Lock()
	udpRemoteForwarderList = append(udpRemoteForwarderList, f)
	udpRemoteForwarderMutex.Unlock()

	done1 := make(chan struct{})
	done2 := make(chan struct{})

	go func() {
		defer close(done1)
		var warnOnce sync.Once
		_ = f.remoteConn.Consume(func(buf []byte) error {
			f.lastActive.Store(time.Now().Unix())
			if _, err := f.localConn.Write(buf); err != nil {
				if isClosedError(err) {
					debug("udp remote forwarding [%s] write to local closed: %v", f.fwdConfig, err)
					return err
				}
				warnOnce.Do(func() {
					warning("udp remote forwarding [%s] write to local failed: %v", f.fwdConfig, err)
				})
			}
			return nil
		})
	}()

	go func() {
		defer close(done2)
		buffer := make([]byte, 0xffff)
		for {
			n, err := f.localConn.Read(buffer)
			if err != nil {
				if isClosedError(err) {
					debug("udp remote forwarding [%s] read from local closed: %v", f.fwdConfig, err)
					return
				}
				warning("udp remote forwarding [%s] read from local failed: %v", f.fwdConfig, err)
				return
			}
			f.lastActive.Store(time.Now().Unix())
			if err := f.remoteConn.Write(buffer[:n]); err != nil {
				if isClosedError(err) {
					debug("udp remote forwarding [%s] write to remote closed: %v", f.fwdConfig, err)
					return
				}
				warning("udp remote forwarding [%s] write to remote failed: %v", f.fwdConfig, err)
				return
			}
		}
	}()

	select {
	case <-done1:
	case <-done2:
	}

	udpRemoteForwarderMutex.Lock()
	for i, fwd := range udpRemoteForwarderList {
		if fwd == f {
			udpRemoteForwarderList[i] = udpRemoteForwarderList[len(udpRemoteForwarderList)-1]
			udpRemoteForwarderList[len(udpRemoteForwarderList)-1] = nil
			udpRemoteForwarderList = udpRemoteForwarderList[:len(udpRemoteForwarderList)-1]
			break
		}
	}
	udpRemoteForwarderMutex.Unlock()
}

func (f *udpRemoteForwarder) cleanupTimeout(fwdExpireBefore int64) {
	if f.lastActive.Load() < fwdExpireBefore {
		f.Close()
	}
}

func udpForwarderCleanup(args *sshArgs) {
	udpForwradTimeoutHandlerOnce.Do(func() {
		var timeout time.Duration
		if forwardUdpTimeout := getOptionConfig(args, "ForwardUdpTimeout"); forwardUdpTimeout != "" {
			seconds, err := convertSshTime(forwardUdpTimeout)
			if err != nil {
				warning("ForwardUdpTimeout [%s] invalid: %v", forwardUdpTimeout, err)
			} else {
				timeout = time.Duration(seconds) * time.Second
			}
		}
		if timeout <= 0 {
			timeout = kDefaultForwardUdpTimeout
		}

		go func() {
			sleepTime := max(timeout/5, time.Second)
			fwdTimeoutSeconds := int64(timeout / time.Second)
			for {
				time.Sleep(sleepTime)

				udpLocalForwarderMutex.Lock()
				localForwarders := append([]*udpLocalForwarder(nil), udpLocalForwarderList...)
				udpLocalForwarderMutex.Unlock()

				udpRemoteForwarderMutex.Lock()
				remoteForwarders := append([]*udpRemoteForwarder(nil), udpRemoteForwarderList...)
				udpRemoteForwarderMutex.Unlock()

				now := time.Now().Unix()
				fwdExpireBefore := now - fwdTimeoutSeconds
				warnExpireBefore := now - kWarnIntervalSeconds
				for _, fwd := range localForwarders {
					fwd.cleanupTimeout(fwdExpireBefore, warnExpireBefore)
				}
				for _, fwd := range remoteForwarders {
					fwd.cleanupTimeout(fwdExpireBefore)
				}
			}
		}()
	})
}

func cloneNetAddr(addr net.Addr) net.Addr {
	switch v := addr.(type) {
	case *net.UDPAddr:
		return &net.UDPAddr{
			IP:   append([]byte(nil), v.IP...),
			Port: v.Port,
			Zone: v.Zone,
		}
	case *net.IPAddr:
		return &net.IPAddr{
			IP:   append([]byte(nil), v.IP...),
			Zone: v.Zone,
		}
	case *net.UnixAddr:
		return &net.UnixAddr{
			Name: v.Name,
			Net:  v.Net,
		}
	default:
		return addr
	}
}

func listenOnLocalUDP(gateway bool, addr *string, port, name string) (conns []net.PacketConn) {
	listen := func(network, address string) {
		conn, err := net.ListenPacket(network, address)
		if err != nil {
			warning("%s listen on local [%s] [%s] failed: %v", name, network, address, err)
		} else {
			debug("%s listen on local [%s] [%s] success", name, network, address)
			conns = append(conns, conn)
			addOnCloseFunc(func() {
				_ = conn.Close()
				if network == "unixgram" {
					if err := os.Remove(address); err != nil {
						debug("remove unix socket [%s] failed: %v", address, err)
					}
				}
			})
		}
	}

	if addr == nil && gateway || addr != nil && (*addr == "" || *addr == "*") {
		listen("udp4", joinHostPort("0.0.0.0", port))
		listen("udp6", joinHostPort("::", port))
		return
	}

	if addr == nil {
		listen("udp4", joinHostPort("127.0.0.1", port))
		listen("udp6", joinHostPort("::1", port))
		return
	}

	if strings.HasPrefix(*addr, "/") && port == "-1" {
		listen("unixgram", *addr)
		return
	}

	listen("udp", joinHostPort(*addr, port))
	return
}

func localForwardUDP(sshConn *sshConnection, f *forwardCfg, gateway bool, timeout time.Duration) {
	var remoteNet, remoteAddr string
	if f.destPort == -1 && strings.HasPrefix(f.destHost, "/") {
		remoteNet = "unixgram"
		remoteAddr = f.destHost
	} else {
		remoteNet = "udp"
		remoteAddr = joinHostPort(f.destHost, strconv.Itoa(f.destPort))
	}

	name := fmt.Sprintf("local forwarding [%v]", f)
	for _, conn := range listenOnLocalUDP(gateway, f.bindAddr, strconv.Itoa(f.bindPort), name) {
		forwarder := &udpLocalForwarder{
			client:      sshConn.client,
			timeout:     timeout,
			remoteNet:   remoteNet,
			remoteAddr:  remoteAddr,
			localConn:   conn,
			fwdConfig:   f,
			fwdSessions: make(map[string]*udpForwardSession),
			lastWarn:    make(map[string]int64),
		}
		go forwarder.run()
		udpForwarderCleanup(sshConn.param.args)
	}
}

func listenOnRemoteUDP(gateway bool, client SshClient, f *forwardCfg) (listeners []PacketListener) {
	addr, port := f.bindAddr, strconv.Itoa(f.bindPort)
	listen := func(network, address string) {
		listener, err := client.ListenUDP(network, address)
		if err != nil {
			if network == "udp6" {
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

	if addr == nil && gateway || addr != nil && (*addr == "" || *addr == "*") {
		listen("udp4", joinHostPort("0.0.0.0", port))
		listen("udp6", joinHostPort("::", port))
		return
	}

	if addr == nil {
		listen("udp4", joinHostPort("127.0.0.1", port))
		listen("udp6", joinHostPort("::1", port))
		return
	}

	if strings.HasPrefix(*addr, "/") && port == "-1" {
		listen("unixgram", *addr)
		return
	}

	listen("udp", joinHostPort(*addr, port))
	return
}

func remoteForwardUDP(sshConn *sshConnection, f *forwardCfg, gateway bool, timeout time.Duration) {
	var localNet, localAddr string
	if f.destPort == -1 && strings.HasPrefix(f.destHost, "/") {
		localNet = "unixgram"
		localAddr = f.destHost
	} else {
		localNet = "udp"
		localAddr = joinHostPort(f.destHost, strconv.Itoa(f.destPort))
	}

	for _, listener := range listenOnRemoteUDP(gateway, sshConn.client, f) {
		udpForwarderCleanup(sshConn.param.args)

		go func(listener PacketListener) {
			defer func() { _ = listener.Close() }()
			for {
				remoteConn, err := listener.AcceptUDP()
				if err != nil {
					if isClosedError(err) {
						debug("remote forwarding [%v] closed: %v", f, err)
						break
					}
					warning("remote forwarding [%v] accept failed: %v", f, err)
					break
				}

				localConn, err := dialUDP(localNet, localAddr, timeout)
				if err != nil {
					warning("remote forwarding [%v] dial [%s] [%s] failed: %v", f, localNet, localAddr, err)
					_ = remoteConn.Close()
					continue
				}

				forwarder := &udpRemoteForwarder{
					localConn:  localConn,
					remoteConn: remoteConn,
					fwdConfig:  f,
				}
				go forwarder.run()
			}
		}(listener)
	}
}

type unixgramConn struct {
	io.ReadWriteCloser
	localAddr string
}

func (c *unixgramConn) Close() error {
	err := c.ReadWriteCloser.Close()
	_ = os.Remove(c.localAddr)
	return err
}

func dialUDP(network, address string, timeout time.Duration) (io.ReadWriteCloser, error) {
	if network == "unixgram" {
		tmpFile, err := os.CreateTemp("", "tssh_unixgram_*.sock")
		if err != nil {
			return nil, fmt.Errorf("create temp file failed: %v", err)
		}
		localAddr := tmpFile.Name()
		if err := tmpFile.Close(); err != nil {
			return nil, fmt.Errorf("close temp file failed: %v", err)
		}
		if err := os.Remove(localAddr); err != nil {
			return nil, fmt.Errorf("remove temp file failed: %v", err)
		}
		laddr := &net.UnixAddr{Net: "unixgram", Name: localAddr}
		raddr := &net.UnixAddr{Net: "unixgram", Name: address}
		conn, err := net.DialUnix("unixgram", laddr, raddr)
		if err != nil {
			if _, err := os.Stat(localAddr); err == nil {
				_ = os.Remove(localAddr)
			}
			return nil, err
		}
		return &unixgramConn{conn, localAddr}, nil
	}

	var err error
	var addr *net.UDPAddr
	if timeout > 0 {
		addr, err = doWithTimeout(func() (*net.UDPAddr, error) {
			return net.ResolveUDPAddr(network, address)
		}, timeout)
	} else {
		addr, err = net.ResolveUDPAddr(network, address)
	}
	if err != nil {
		return nil, err
	}

	return net.DialUDP(network, nil, addr)
}

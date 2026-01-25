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
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var udpLocalForwarderList []*udpLocalForwarder
var udpLocalForwarderOnce sync.Once
var udpLocalForwarderMutex sync.Mutex

const kWarnIntervalSeconds = 60
const kDefaultForwardUdpTimeout = 5 * time.Minute

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
		f.fwdSessions[clientKey] = session

		go func() {
			defer func() {
				_ = session.remoteConn.Close()
				f.mutex.Lock()
				defer f.mutex.Unlock()
				delete(f.fwdSessions, clientKey)
			}()
			if err := conn.Consume(func(data []byte) error {
				session.lastActive.Store(time.Now().Unix())
				if _, err := f.localConn.WriteTo(data, clientAddr); err != nil {
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

func udpLocalForwarderCleanup(args *sshArgs) {
	udpLocalForwarderOnce.Do(func() {
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
				forwarders := append([]*udpLocalForwarder(nil), udpLocalForwarderList...)
				udpLocalForwarderMutex.Unlock()

				now := time.Now().Unix()
				fwdExpireBefore := now - fwdTimeoutSeconds
				warnExpireBefore := now - kWarnIntervalSeconds
				for _, fwd := range forwarders {
					fwd.cleanupTimeout(fwdExpireBefore, warnExpireBefore)
				}
			}
		}()
	})
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
		udpLocalForwarderCleanup(sshConn.param.args)
	}
}

var warnOnce sync.Once

func remoteForwardUDP(sshConn *sshConnection, f *forwardCfg, gateway bool, timeout time.Duration) {
	warnOnce.Do(func() {
		warning("UDP remote forwarding has not been implemented yet") // TODO
		_, _, _, _ = sshConn, f, gateway, timeout
	})
}

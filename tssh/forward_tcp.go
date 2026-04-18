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
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/trzsz/go-socks5"
)

// OpenSSH's default StreamLocalBindMask.
const defaultStreamLocalBindMask = 0177

// streamLocalBindMask returns the StreamLocalBindMask for the given ssh args,
// falling back to OpenSSH's default when unset or invalid.
func streamLocalBindMask(args *sshArgs) int {
	v := getOptionConfig(args, "StreamLocalBindMask")
	if v == "" {
		return defaultStreamLocalBindMask
	}
	mask, err := strconv.ParseInt(v, 8, 32)
	if err != nil || mask < 0 || mask > 0777 {
		warning("invalid StreamLocalBindMask [%s], using default 0177", v)
		return defaultStreamLocalBindMask
	}
	return int(mask)
}

// unlinkStaleUnixSocket honors StreamLocalBindUnlink for local unix sockets.
// Missing paths are a no-op. Non-socket files are refused. Socket files are
// removed and a debug log is emitted.
func unlinkStaleUnixSocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to unlink non-socket path: %s", path)
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	debug("unlinked existing unix socket [%s] per StreamLocalBindUnlink", path)
	return nil
}

type cleanupListener struct {
	net.Listener
	cleanup func() error
}

func (l *cleanupListener) Close() error {
	return l.cleanup()
}

func listenOnLocalTCP(gateway bool, addr *string, port, name string, unlinkUnix bool, bindMask int) (listeners []net.Listener) {
	listen := func(network, address string) {
		if unlinkUnix && network == "unix" {
			if err := unlinkStaleUnixSocket(address); err != nil {
				warning("%s unlink [%s] failed: %v", name, address, err)
				return
			}
		}

		listener, err := net.Listen(network, address)
		if err != nil {
			warning("%s listen on local [%s] [%s] failed: %v", name, network, address, err)
			return
		}

		if network == "unix" {
			mode := os.FileMode(0666) &^ os.FileMode(bindMask)
			if err := os.Chmod(address, mode); err != nil {
				warning("%s chmod unix socket [%s] to %#o failed: %v", name, address, mode, err)
			}
			listener = &cleanupListener{listener, newFileUnlinker(address, listener)}
		}

		debug("%s listen on local [%s] [%s] success", name, network, address)
		listeners = append(listeners, listener)
		addOnCloseFunc(func() { _ = listener.Close() })
	}

	if addr == nil && gateway || addr != nil && (*addr == "" || *addr == "*") {
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

func listenOnRemoteTCP(gateway bool, client SshClient, f *forwardCfg) (listeners []net.Listener) {
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

	if addr == nil && gateway || addr != nil && (*addr == "" || *addr == "*") {
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

type sshResolver struct{}

func (d sshResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	return ctx, []byte{}, nil
}

func dynamicForward(sshConn *sshConnection, b *bindCfg, gateway bool, timeout time.Duration, unlinkUnix bool, bindMask int) {
	var dialError = errors.New("DIAL_ERROR_" + uuid.NewString())
	server, err := socks5.New(&socks5.Config{
		Resolver: &sshResolver{},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := sshConn.client.DialTimeout(network, addr, timeout)
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
	for _, listener := range listenOnLocalTCP(gateway, b.addr, strconv.Itoa(b.port), name, unlinkUnix, bindMask) {
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

func localForwardTCP(sshConn *sshConnection, f *forwardCfg, gateway bool, timeout time.Duration, unlinkUnix bool, bindMask int) {
	var remoteNet, remoteAddr string
	if f.destPort == -1 && strings.HasPrefix(f.destHost, "/") {
		remoteNet = "unix"
		remoteAddr = f.destHost
	} else {
		remoteNet = "tcp"
		remoteAddr = joinHostPort(f.destHost, strconv.Itoa(f.destPort))
	}

	name := fmt.Sprintf("local forwarding [%v]", f)
	for _, listener := range listenOnLocalTCP(gateway, f.bindAddr, strconv.Itoa(f.bindPort), name, unlinkUnix, bindMask) {
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
				remote, err := sshConn.client.DialTimeout(remoteNet, remoteAddr, timeout)
				if err != nil {
					if reason := forwardDeniedReason(err, remoteNet); reason != "" {
						warning("The local forwarding [%v] was denied. %s", f, reason)
					} else {
						warning("local forwarding [%v] dial [%s] [%s] failed: %v", f, remoteNet, remoteAddr, err)
					}
					_ = local.Close()
					continue
				}
				go tcpForward(local, remote)
			}
		}(listener)
	}
}

func remoteForwardTCP(sshConn *sshConnection, f *forwardCfg, gateway bool, timeout time.Duration) {
	var localNet, localAddr string
	if f.destPort == -1 && strings.HasPrefix(f.destHost, "/") {
		localNet = "unix"
		localAddr = f.destHost
	} else {
		localNet = "tcp"
		localAddr = joinHostPort(f.destHost, strconv.Itoa(f.destPort))
	}

	for _, listener := range listenOnRemoteTCP(gateway, sshConn.client, f) {
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
				local, err := net.DialTimeout(localNet, localAddr, timeout)
				if err != nil {
					warning("remote forwarding [%v] dial [%s] [%s] failed: %v", f, localNet, localAddr, err)
					_ = remote.Close()
					continue
				}
				go tcpForward(local, remote)
			}
		}(listener)
	}
}

func tcpForward(local, remote net.Conn) {
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

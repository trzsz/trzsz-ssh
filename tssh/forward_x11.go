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
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/trzsz/ssh_config"
	"golang.org/x/crypto/ssh"
)

type x11Request struct {
	SingleConnection bool
	AuthProtocol     string
	AuthCookie       string
	ScreenNumber     uint32
}

func sshX11Forward(sshConn *sshConnection) {
	args := sshConn.param.args
	if args.NoX11Forward || !args.X11Forward && !args.X11Trusted && strings.ToLower(getOptionConfig(args, "ForwardX11")) != "yes" {
		return
	}

	if sshConn.param.control && sshConn.param.udpMode == kUdpModeNo {
		warning("X11 forwarding is not supported when logging in via a control socket")
		return
	}

	display := os.Getenv("DISPLAY")
	if display == "" {
		warning("X11 forwarding is not working due to environment variable DISPLAY is not set")
		return
	}
	hostname, displayNumber, screenNumber, err := resolveDisplayEnv(display)
	if err != nil {
		warning("X11 forwarding is not working due to: %v", err)
		return
	}

	trusted := func() bool {
		if args.X11Trusted {
			// -Y forces trusted forwarding
			return true
		}

		ssh_config.SetDefault("ForwardX11Trusted", "")
		switch strings.ToLower(getOptionConfig(args, "ForwardX11Trusted")) {
		case "yes":
			return true
		case "no":
			return false
		default:
			if isRunningInRemoteSsh() {
				// If running in a remote SSH session, default to trusted (following Debian-specific behavior)
				return true
			}
			// Otherwise, default to untrusted (following OpenSSH upstream behavior)
			return false
		}
	}()

	timeout := uint32(1200)
	forwardX11Timeout := getOptionConfig(args, "ForwardX11Timeout")
	if forwardX11Timeout != "" && strings.ToLower(forwardX11Timeout) != "none" {
		seconds, err := convertSshTime(forwardX11Timeout)
		if err != nil {
			warning("ForwardX11Timeout [%s] invalid: %v", forwardX11Timeout, err)
		} else {
			timeout = seconds
		}
	}

	xauthData, err := getXauthInfo(sshConn.param.args, display, trusted, timeout)
	if err != nil {
		warning("X11 forwarding is not working due to xauth failed: %v", err)
		return
	}
	if enableDebugLogging {
		n := min(3, len(xauthData.fakeCookie)/2)
		debug("xauth fake cookie: %x%s", xauthData.fakeCookie[:n], strings.Repeat("*", (len(xauthData.fakeCookie)-n)*2))
	}

	payload := x11Request{
		SingleConnection: false,
		AuthProtocol:     xauthData.xauthProto,
		AuthCookie:       fmt.Sprintf("%x", xauthData.fakeCookie),
		ScreenNumber:     screenNumber,
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
		x11Timeout := time.Now().Add(time.Duration(timeout) * time.Second)
		for ch := range channels {
			channel, reqs, err := ch.Accept()
			if err != nil {
				warning("X11 forwarding accept failed: %v", err)
				continue
			}
			go ssh.DiscardRequests(reqs)
			go func() {
				defer func() { _ = channel.Close() }()
				if !trusted && timeout > 0 && time.Now().After(x11Timeout) {
					delayWarning(time.Second, "Rejected X11 connection after ForwardX11Timeout [%s] (%d seconds) expired", forwardX11Timeout, timeout)
					return
				}
				serveX11(display, hostname, displayNumber, channel, xauthData)
			}()
		}
	}()
}

func resolveDisplayEnv(display string) (string, uint32, uint32, error) {
	// Ensure DISPLAY contains only valid characters for security following OpenSSH
	for i := range len(display) {
		b := display[i]
		if (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') ||
			b == ':' || b == '/' || b == '.' || b == '-' || b == '_' {
			continue
		}
		return "", 0, 0, fmt.Errorf("invalid character %q in DISPLAY %q", b, display)
	}

	colon := strings.LastIndex(display, ":")
	if colon < 0 {
		return "", 0, 0, fmt.Errorf("no ':' in DISPLAY %q", display)
	}
	hostname := display[:colon]

	tokens := strings.Split(display[colon+1:], ".")
	var displayNumber, screenNumber string
	switch len(tokens) {
	case 1:
		displayNumber = tokens[0]
	case 2:
		displayNumber, screenNumber = tokens[0], tokens[1]
	default:
		return "", 0, 0, fmt.Errorf("too many '.' in DISPLAY %q", display)
	}

	dn, err := strconv.ParseUint(displayNumber, 10, 32)
	if err != nil {
		return "", 0, 0, fmt.Errorf("invalid display number in DISPLAY %q: %v", display, err)
	}

	sn := uint64(0)
	if screenNumber != "" {
		sn, err = strconv.ParseUint(screenNumber, 10, 32)
		if err != nil {
			return "", 0, 0, fmt.Errorf("invalid screen number in DISPLAY %q: %v", display, err)
		}
	}

	return hostname, uint32(dn), uint32(sn), nil
}

func serveX11(display, hostname string, displayNumber uint32, channel ssh.Channel, xauthData *xauthInfo) {
	packet, err := substituteX11Packet(channel, xauthData)
	if err != nil {
		delayWarning(time.Second, "Rejected X11 connection: %v", err)
		return
	}

	var conn net.Conn
	if strings.HasPrefix(display, "/") {
		conn, err = net.DialTimeout("unix", display, time.Second)
	} else if hostname != "" {
		conn, err = net.DialTimeout("tcp", joinHostPort(hostname, strconv.Itoa(6000+int(displayNumber))), time.Second)
	} else {
		conn, err = net.DialTimeout("unix", fmt.Sprintf("/tmp/.X11-unix/X%d", displayNumber), time.Second)
	}
	if err != nil {
		delayWarning(time.Second, "X11 forwarding dial [%s] failed: %v", display, err)
		return
	}

	if err := writeAll(conn, packet); err != nil {
		delayWarning(time.Second, "X11 forwarding write to [%s] failed: %v", display, err)
		return
	}

	forwardChannel(channel, conn)
}

func substituteX11Packet(channel ssh.Channel, xauthData *xauthInfo) ([]byte, error) {
	// ---- 1. read fixed header (at least 12 bytes) ----
	packetBuffer := make([]byte, 4096)
	n, err := io.ReadAtLeast(channel, packetBuffer, 12)
	if err != nil {
		return nil, fmt.Errorf("read header failed: %v", err)
	}
	packetBuffer = packetBuffer[:n]

	// ---- 2. parse lengths according to byte order ----
	var protoLen, cookieLen int
	switch packetBuffer[0] {
	case 0x42: // MSB first
		protoLen = int(packetBuffer[6])<<8 + int(packetBuffer[7])
		cookieLen = int(packetBuffer[8])<<8 + int(packetBuffer[9])
	case 0x6c: // LSB first
		protoLen = int(packetBuffer[6]) + int(packetBuffer[7])<<8
		cookieLen = int(packetBuffer[8]) + int(packetBuffer[9])<<8
	default:
		return nil, fmt.Errorf("bad byte order byte: %#x", packetBuffer[0])
	}
	if protoLen != len(xauthData.xauthProto) {
		return nil, fmt.Errorf("proto length mismatch: packet=%d local=%d", protoLen, len(xauthData.xauthProto))
	}
	if cookieLen != len(xauthData.fakeCookie) || cookieLen != len(xauthData.realCookie) {
		return nil, fmt.Errorf("cookie length mismatch: packet=%d fake=%d real=%d",
			cookieLen, len(xauthData.fakeCookie), len(xauthData.realCookie))
	}

	// padding to 4 bytes
	paddedProtoLen := (protoLen + 3) &^ 3
	paddedCookieLen := (cookieLen + 3) &^ 3
	fullHeaderLen := 12 + paddedProtoLen + paddedCookieLen
	if fullHeaderLen > cap(packetBuffer) {
		return nil, fmt.Errorf("packet too large: %d bytes", fullHeaderLen)
	}

	// ---- 3. read rest of packet if not enough ----
	if len(packetBuffer) < fullHeaderLen {
		if _, err := io.ReadFull(channel, packetBuffer[len(packetBuffer):fullHeaderLen]); err != nil {
			return nil, fmt.Errorf("read packet failed: %v", err)
		}
		packetBuffer = packetBuffer[:fullHeaderLen]
	}

	// ---- 4. check authentication protocol ----
	protoBuffer := packetBuffer[12 : 12+protoLen]
	if string(protoBuffer) != xauthData.xauthProto {
		return nil, fmt.Errorf("auth proto mismatch: packet=%s local=%s", protoBuffer, xauthData.xauthProto)
	}

	// ---- 5. check fake cookie ----
	cookieOffset := 12 + paddedProtoLen
	cookieBuffer := packetBuffer[cookieOffset : cookieOffset+cookieLen]

	if !bytes.Equal(cookieBuffer, xauthData.fakeCookie) {
		n := min(3, cookieLen/2)
		return nil, fmt.Errorf("authentication cookie mismatch: packet=%x*** local=%x***",
			cookieBuffer[:n], xauthData.fakeCookie[:n])
	}

	// ---- 6. substitute cookie in memory ----
	copy(cookieBuffer, xauthData.realCookie)

	return packetBuffer, nil
}

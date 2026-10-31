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
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trzsz/tsshd/tsshd"
)

func TestParseTsshdPortRanges(t *testing.T) {
	enableWarning := enableWarningLogging
	enableWarningLogging = false
	defer func() { enableWarningLogging = enableWarning }()

	assert := assert.New(t)
	assert.Equal([][2]uint16{{22, 22}}, parseTsshdPortRanges("22"))
	assert.Equal([][2]uint16{{100, 102}}, parseTsshdPortRanges("100-102"))
	assert.Equal([][2]uint16{{200, 202}}, parseTsshdPortRanges("200 - 202"))
	assert.Equal([][2]uint16{{10, 10}, {20, 20}, {30, 30}}, parseTsshdPortRanges("10 20 30"))
	assert.Equal([][2]uint16{{1, 3}, {5, 5}, {7, 9}, {11, 11}}, parseTsshdPortRanges("1-3 5,7 - 9 11"))
	assert.Equal([][2]uint16{{1, 2}, {3, 4}, {5, 5}}, parseTsshdPortRanges("1-2,3-4 5"))
	assert.Equal([][2]uint16{{10, 12}, {15, 15}}, parseTsshdPortRanges("  10\t-\t12  , 15 "))
	assert.Equal([][2]uint16{{50, 50}}, parseTsshdPortRanges("50-50"))
	assert.Equal([][2]uint16{{10, 10}, {20, 20}}, parseTsshdPortRanges("10,,20"))
	assert.Equal([][2]uint16(nil), parseTsshdPortRanges("0,70000,abc"))
	assert.Equal([][2]uint16(nil), parseTsshdPortRanges("100-50"))
	assert.Equal([][2]uint16(nil), parseTsshdPortRanges("-"))
	assert.Equal([][2]uint16(nil), parseTsshdPortRanges("- 10"))
	assert.Equal([][2]uint16(nil), parseTsshdPortRanges("10 -"))
	assert.Equal([][2]uint16{{1, 3}, {7, 7}}, parseTsshdPortRanges("1-3,abc,5 - 4,7"))
	assert.Equal([][2]uint16(nil), parseTsshdPortRanges(""))
	assert.Equal([][2]uint16(nil), parseTsshdPortRanges("8000-9000-10000"))
	assert.Equal([][2]uint16(nil), parseTsshdPortRanges("8000-"))
	assert.Equal([][2]uint16(nil), parseTsshdPortRanges("-9000"))
	assert.Equal([][2]uint16{{10, 12}}, parseTsshdPortRanges("10 - 12 - 15"))
	assert.Equal([][2]uint16{{1, 65535}}, parseTsshdPortRanges("1-65535"))
	assert.Equal([][2]uint16{{10, 10}, {10, 10}, {10, 10}}, parseTsshdPortRanges("10 10 10"))
	assert.Equal([][2]uint16{{20, 25}, {22, 23}}, parseTsshdPortRanges("20-25 22-23"))
	assert.Equal([][2]uint16(nil), parseTsshdPortRanges("10 - 0"))
	assert.Equal([][2]uint16(nil), parseTsshdPortRanges("10 - - 11"))
	assert.Equal([][2]uint16{{10, 11}}, parseTsshdPortRanges("10 - 11 -"))
}

func TestUdpAddressFamily(t *testing.T) {
	oldPreflight := udpPreflight
	defer func() { udpPreflight = oldPreflight }()

	for _, tc := range []struct {
		name, advertised, config string
		flag4, flag6, ssh4, ssh6 bool
		proxied, unreachable     bool
		want4, want6, preflight  bool
	}{
		{name: "ControlPathIPv6", advertised: "inet6", want6: true},
		{name: "ControlPathIPv4", advertised: "inet", want4: true},
		{name: "AttachOverIPv4", advertised: "inet6", ssh4: true, want6: true, preflight: true},
		{name: "AttachOverIPv6", advertised: "inet", ssh6: true, want4: true, preflight: true},
		{name: "SameFamilyNoPreflight", advertised: "inet", ssh4: true, want4: true},
		{name: "NAT64FallsBackToSSH", advertised: "inet", ssh6: true, unreachable: true, want6: true, preflight: true},
		{name: "UnreachableNoFallback", advertised: "inet6", unreachable: true, want6: true},
		{name: "ProxySkipsPreflight", advertised: "inet", ssh6: true, proxied: true, unreachable: true, want4: true},
		{name: "OldServerInferred", ssh6: true, want6: true},
		{name: "OldServerUnknown"},
		{name: "OldServerAmbiguous", ssh4: true, ssh6: true},
		{name: "FutureUnknownFamily", advertised: "future", ssh4: true, want4: true},
		{name: "ExplicitOverridesSSH", flag4: true, ssh6: true, want4: true},
		{name: "ExplicitMatches", flag6: true, advertised: "inet6", ssh4: true, want6: true},
		{name: "ExplicitWins4", flag4: true, advertised: "inet6", want4: true},
		{name: "ExplicitWins6NAT64", flag6: true, advertised: "inet", ssh6: true, want6: true},
		{name: "ConfigInet", config: "inet", ssh6: true, want4: true},
		{name: "ConfigInet6", config: "INET6", ssh4: true, want6: true},
		{name: "ConfigWins", config: "inet6", advertised: "inet", want6: true},
		{name: "ConfigAny", config: "any", advertised: "inet6", want6: true},
		{name: "FlagOverridesConfig", flag4: true, config: "inet6", advertised: "inet", want4: true},
		{name: "BothFlagsUnrestricted", flag4: true, flag6: true, advertised: "inet6", want6: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.config == "" {
				tc.config = "any"
			}
			var preflighted string
			udpPreflight = func(network, addr string) error {
				preflighted = network + " " + addr
				if tc.unreachable {
					return syscall.ENETUNREACH
				}
				return nil
			}
			args := &sshArgs{IPv4Only: tc.flag4, IPv6Only: tc.flag6,
				Option: sshOption{options: map[string][]string{"addressfamily": {tc.config}}}}
			param := &sshParam{args: args, ipv4: tc.ssh4, ipv6: tc.ssh6}
			info := &tsshd.ServerInfo{AddressFamily: tc.advertised}
			ipv4, ipv6 := getUdpAddressFamily(param, info, "host.example:1234", !tc.proxied)
			assert.Equal(t, tc.want4, ipv4)
			assert.Equal(t, tc.want6, ipv6)
			if tc.preflight {
				network := "udp4"
				if tc.advertised == "inet6" {
					network = "udp6"
				}
				assert.Equal(t, network+" host.example:1234", preflighted)
			} else {
				assert.Empty(t, preflighted)
			}
		})
	}
}

func TestUdpPreflight(t *testing.T) {
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("IPv4 loopback unavailable: %v", err)
	}
	defer listener.Close()
	addr := listener.LocalAddr().String()
	assert.NoError(t, udpPreflight("udp4", addr))
	assert.Error(t, udpPreflight("udp6", addr))
}

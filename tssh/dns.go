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
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/dns/dnsmessage"
)

// customDnsServer records the DNS server configured via setDNS, so that SSHFP
// lookups (which the stdlib resolver can't perform) can reuse the same server.
var customDnsServer struct {
	network string
	addr    string
}

// setDNS sets the net.DefaultResolver to use the given DNS server.
func setDNS(dns string) {

	network, dns, err := resolveDnsAddress(dns)
	if err != nil {
		return

	}

	customDnsServer.network = network
	customDnsServer.addr = dns

	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, addr string) (net.Conn, error) {
			debug("use custom DNS: %s://%s", network, dns)
			var d net.Dialer
			return d.DialContext(ctx, network, dns)
		},
	}

}

func resolveDnsAddress(dns string) (string, string, error) {

	var preParseDns string
	if !strings.Contains(dns, "://") {
		preParseDns = "udp://" + dns
	} else {
		preParseDns = dns
	}

	svrParse, err := url.Parse(preParseDns)
	if err != nil {
		warning("parse dns [%s] failed: %v", dns, err)
		return "", "", err

	}

	var network string
	switch strings.ToLower(svrParse.Scheme) {
	case "tcp":
		network = "tcp"
	default:
		network = "udp"
	}

	host, port, err := net.SplitHostPort(svrParse.Host)
	if err != nil {
		// If no port is specified, use default port 53
		host = svrParse.Host
		port = "53"
	}

	dns = net.JoinHostPort(host, port)
	return network, dns, nil

}

func lookupDnsSrv(name string) (string, string, error) {
	_, addrs, err := net.LookupSRV("ssh", "tcp", name)
	if err != nil {
		return "", "", err
	}
	if len(addrs) == 0 {
		return "", "", fmt.Errorf("no srv record")
	}
	host := strings.TrimRight(addrs[0].Target, ".")
	port := addrs[0].Port
	return host, strconv.Itoa(int(port)), nil
}

// SSHFP fingerprint type values (RFC 4255 / RFC 6594).
const (
	sshfpTypeSHA1   = 1
	sshfpTypeSHA256 = 2
)

// sshfpRecord is a parsed SSHFP (DNS type 44) resource record.
type sshfpRecord struct {
	algorithm   uint8
	fpType      uint8
	fingerprint []byte
}

// sshfpAlgorithm maps an SSH public key type to its SSHFP algorithm number
// (RFC 4255 / RFC 6594 / RFC 7479). It returns 0 for unsupported types.
func sshfpAlgorithm(keyType string) uint8 {
	switch keyType {
	case ssh.KeyAlgoRSA:
		return 1
	case ssh.KeyAlgoDSA:
		return 2
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		return 3
	case ssh.KeyAlgoED25519:
		return 4
	default:
		return 0
	}
}

// matchSSHFP reports whether the presented host key matches any of the given
// SSHFP records. A record matches when its algorithm equals the key's SSHFP
// algorithm and its fingerprint equals the SHA-1 or SHA-256 digest of the raw
// public key blob.
func matchSSHFP(records []sshfpRecord, key ssh.PublicKey) bool {
	algorithm := sshfpAlgorithm(key.Type())
	if algorithm == 0 {
		return false
	}
	blob := key.Marshal()
	sha1Sum := sha1.Sum(blob)
	sha256Sum := sha256.Sum256(blob)
	for _, record := range records {
		if record.algorithm != algorithm {
			continue
		}
		switch record.fpType {
		case sshfpTypeSHA1:
			if bytesEqual(record.fingerprint, sha1Sum[:]) {
				return true
			}
		case sshfpTypeSHA256:
			if bytesEqual(record.fingerprint, sha256Sum[:]) {
				return true
			}
		}
	}
	return false
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// parseSSHFP extracts the SSHFP records from the answers of a DNS response.
func parseSSHFP(answers []dnsmessage.Resource) []sshfpRecord {
	var records []sshfpRecord
	for _, answer := range answers {
		if answer.Header.Type != dnsmessage.Type(44) {
			continue
		}
		unknown, ok := answer.Body.(*dnsmessage.UnknownResource)
		if !ok {
			continue
		}
		data := unknown.Data
		if len(data) < 3 {
			continue
		}
		records = append(records, sshfpRecord{
			algorithm:   data[0],
			fpType:      data[1],
			fingerprint: append([]byte(nil), data[2:]...),
		})
	}
	return records
}

// dnsServers returns the DNS server addresses to use for SSHFP lookups. It
// prefers a server configured via setDNS and otherwise falls back to the
// system nameservers from /etc/resolv.conf.
func dnsServers() []string {
	if customDnsServer.addr != "" {
		return []string{customDnsServer.addr}
	}
	return systemDnsServers()
}

// verifyHostKeyDNS reports whether the presented host key matches an SSHFP
// record published in DNS for the host. The host may include a port, which is
// stripped before the lookup. Any lookup failure is treated as no match.
func verifyHostKeyDNS(host string, key ssh.PublicKey) bool {
	name := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		name = h
	}
	name = strings.Trim(name, "[]")
	if name == "" || net.ParseIP(name) != nil {
		// SSHFP records are keyed by hostname; skip bare IP addresses.
		return false
	}
	records, err := lookupSSHFP(name)
	if err != nil {
		debug("SSHFP lookup for '%s' failed: %v", name, err)
		return false
	}
	return matchSSHFP(records, key)
}

// lookupSSHFP queries DNS for the SSHFP (type 44) records of the given host.
func lookupSSHFP(host string) ([]sshfpRecord, error) {
	servers := dnsServers()
	if len(servers) == 0 {
		return nil, fmt.Errorf("no dns server available for SSHFP lookup")
	}

	name, err := dnsmessage.NewName(dnsName(host))
	if err != nil {
		return nil, err
	}
	query := dnsmessage.Message{
		Header: dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  name,
			Type:  dnsmessage.Type(44),
			Class: dnsmessage.ClassINET,
		}},
	}
	request, err := query.Pack()
	if err != nil {
		return nil, err
	}

	var lastErr error
	for _, server := range servers {
		records, err := querySSHFP(server, request)
		if err != nil {
			lastErr = err
			continue
		}
		return records, nil
	}
	return nil, lastErr
}

func querySSHFP(server string, request []byte) ([]sshfpRecord, error) {
	conn, err := net.DialTimeout("udp", server, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(request); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	var response dnsmessage.Message
	if err := response.Unpack(buf[:n]); err != nil {
		return nil, err
	}
	return parseSSHFP(response.Answers), nil
}

// systemDnsServers returns the nameserver addresses configured in
// /etc/resolv.conf (host:53), best-effort. It returns nil when the file is
// absent or unreadable (for example on Windows), in which case SSHFP lookups
// require a DNS server configured via the -o ... or --dns options.
func systemDnsServers() []string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var servers []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "nameserver") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		servers = append(servers, net.JoinHostPort(fields[1], "53"))
	}
	return servers
}

// dnsName returns a fully qualified domain name (with a trailing dot) for the
// given host, stripping any surrounding brackets.
func dnsName(host string) string {
	host = strings.Trim(host, "[]")
	if !strings.HasSuffix(host, ".") {
		host += "."
	}
	return host
}

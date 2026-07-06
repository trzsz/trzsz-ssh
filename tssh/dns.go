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
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	dnsQueryTimeout = 2 * time.Second
	dnsOpCodeQuery  = dnsmessage.OpCode(0)
)

// customDnsServer records the DNS server configured via setDNS, so that SSHFP
// lookups (which the stdlib resolver can't perform) can reuse the same server.
var customDnsServer dnsServer

var dialDNS = net.DialTimeout

type dnsServer struct {
	network         string
	addr            string
	trustedResolver bool
}

// setDNS sets the net.DefaultResolver to use the given DNS server.
func setDNS(dns string) {

	network, dns, err := resolveDnsAddress(dns)
	if err != nil {
		return

	}

	customDnsServer = newDnsServer(network, dns)

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
			if bytes.Equal(record.fingerprint, sha1Sum[:]) {
				return true
			}
		case sshfpTypeSHA256:
			if bytes.Equal(record.fingerprint, sha256Sum[:]) {
				return true
			}
		}
	}
	return false
}

// parseSSHFP extracts the SSHFP records from the answers of a DNS response.
// Only answers whose owner name matches expected are accepted, so a response
// cannot smuggle in records for a different name.
func parseSSHFP(answers []dnsmessage.Resource, expected dnsmessage.Name) []sshfpRecord {
	var records []sshfpRecord
	for _, answer := range answers {
		if answer.Header.Type != dnsmessage.Type(44) {
			continue
		}
		if !strings.EqualFold(answer.Header.Name.String(), expected.String()) {
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

// dnsServers returns the DNS servers to use for SSHFP lookups. It prefers a
// server configured via setDNS and otherwise falls back to system nameservers.
func dnsServers() []dnsServer {
	if customDnsServer.addr != "" {
		return []dnsServer{customDnsServer}
	}
	return systemDnsServers()
}

// verifyHostKeyDNS reports whether the presented host key matches an SSHFP
// record published in DNS for the host, and whether a trusted local resolver
// marked that response as authenticated. The host may include a port, which is
// stripped before the lookup. Any lookup failure is treated as no match.
// Following OpenSSH, callers must only auto-trust a match when authenticated is
// true; an unauthenticated match merely informs the user.
func verifyHostKeyDNS(host string, key ssh.PublicKey) (matched bool, authenticated bool) {
	name := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		name = h
	}
	name = strings.Trim(name, "[]")
	if name == "" || net.ParseIP(name) != nil {
		// SSHFP records are keyed by hostname; skip bare IP addresses.
		return false, false
	}
	records, authenticated, err := lookupSSHFP(name)
	if err != nil {
		debug("SSHFP lookup for '%s' failed: %v", name, err)
		return false, false
	}
	return matchSSHFP(records, key), authenticated
}

// lookupSSHFP queries DNS for the SSHFP (type 44) records of the given host. It
// also reports whether a trusted local validating resolver set the AD bit.
func lookupSSHFP(host string) ([]sshfpRecord, bool, error) {
	servers := dnsServers()
	if len(servers) == 0 {
		return nil, false, fmt.Errorf("no dns server available for SSHFP lookup")
	}

	name, err := dnsmessage.NewName(dnsName(host))
	if err != nil {
		return nil, false, err
	}

	// Use a random transaction ID so an off-path attacker cannot trivially
	// forge a matching UDP response.
	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return nil, false, err
	}
	id := binary.BigEndian.Uint16(idBytes[:])

	query := dnsmessage.Message{
		// Set AD in the query so a validating resolver that understands the
		// bit can return AD on an authenticated response. tssh does not
		// perform DNSSEC validation itself.
		Header: dnsmessage.Header{ID: id, RecursionDesired: true, AuthenticData: true},
		Questions: []dnsmessage.Question{{
			Name:  name,
			Type:  dnsmessage.Type(44),
			Class: dnsmessage.ClassINET,
		}},
	}
	request, err := query.Pack()
	if err != nil {
		return nil, false, err
	}

	var lastErr error
	for _, server := range servers {
		records, authenticated, err := querySSHFP(server, request, id, name)
		if err != nil {
			lastErr = err
			continue
		}
		return records, authenticated, nil
	}
	return nil, false, lastErr
}

func querySSHFP(server dnsServer, request []byte, id uint16, name dnsmessage.Name) ([]sshfpRecord, bool, error) {
	conn, err := dialDNS(server.network, server.addr, dnsQueryTimeout)
	if err != nil {
		return nil, false, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(dnsQueryTimeout))
	if err := writeDNSMessage(conn, server.network, request); err != nil {
		return nil, false, err
	}
	buf, err := readDNSMessage(conn, server.network)
	if err != nil {
		return nil, false, err
	}
	var response dnsmessage.Message
	if err := response.Unpack(buf); err != nil {
		return nil, false, err
	}
	// Reject responses that don't correspond to our query: wrong transaction
	// ID, not a response, a non-query opcode, an error rcode, or a question
	// that doesn't echo the name and type we asked for.
	if !response.Header.Response ||
		response.Header.ID != id ||
		response.Header.OpCode != dnsOpCodeQuery ||
		response.Header.RCode != dnsmessage.RCodeSuccess {
		return nil, false, fmt.Errorf("unexpected dns response for SSHFP query")
	}
	if len(response.Questions) != 1 ||
		response.Questions[0].Type != dnsmessage.Type(44) ||
		response.Questions[0].Class != dnsmessage.ClassINET ||
		!strings.EqualFold(response.Questions[0].Name.String(), name.String()) {
		return nil, false, fmt.Errorf("dns response question mismatch for SSHFP query")
	}
	return parseSSHFP(response.Answers, name), response.Header.AuthenticData && server.trustedResolver, nil
}

func writeDNSMessage(conn net.Conn, network string, request []byte) error {
	if network != "tcp" {
		n, err := conn.Write(request)
		if err == nil && n != len(request) {
			err = io.ErrShortWrite
		}
		return err
	}
	if len(request) > 65535 {
		return fmt.Errorf("dns query too large")
	}
	msg := make([]byte, len(request)+2)
	binary.BigEndian.PutUint16(msg[:2], uint16(len(request)))
	copy(msg[2:], request)
	n, err := conn.Write(msg)
	if err == nil && n != len(msg) {
		err = io.ErrShortWrite
	}
	return err
}

func readDNSMessage(conn net.Conn, network string) ([]byte, error) {
	if network != "tcp" {
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		return buf[:n], nil
	}
	var length [2]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(length[:])
	if n == 0 {
		return nil, fmt.Errorf("empty dns response")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// systemDnsServers returns the system nameserver addresses (host:53),
// best-effort across Linux, macOS, Windows, and Unix-like resolv.conf systems.
func systemDnsServers() []dnsServer {
	switch runtime.GOOS {
	case "darwin":
		if servers := darwinDnsServers(); len(servers) > 0 {
			return servers
		}
	case "windows":
		return windowsDnsServers()
	}
	return resolvConfDnsServers()
}

func darwinDnsServers() []dnsServer {
	data, err := exec.Command("scutil", "--dns").Output()
	if err != nil {
		return nil
	}
	return parseScutilDnsServers(string(data))
}

func windowsDnsServers() []dnsServer {
	data, err := exec.Command("powershell.exe", "-NoProfile", "-Command",
		"Get-DnsClientServerAddress | Select-Object -ExpandProperty ServerAddresses").Output()
	if err == nil {
		if servers := parseDnsServerAddresses(string(data)); len(servers) > 0 {
			return servers
		}
	}
	data, err = exec.Command("ipconfig", "/all").Output()
	if err != nil {
		return nil
	}
	return parseWindowsIpconfigDnsServers(string(data))
}

func resolvConfDnsServers() []dnsServer {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	return parseResolvConfDnsServers(string(data))
}

func parseResolvConfDnsServers(data string) []dnsServer {
	var servers []dnsServer
	seen := make(map[string]bool)
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "nameserver") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		servers = appendDnsServer(servers, seen, fields[1])
	}
	return servers
}

func parseScutilDnsServers(data string) []dnsServer {
	var servers []dnsServer
	seen := make(map[string]bool)
	for _, line := range strings.Split(data, "\n") {
		if !strings.Contains(strings.ToLower(line), "nameserver") {
			continue
		}
		servers = appendDnsServersFromText(servers, seen, line)
	}
	return servers
}

func parseWindowsIpconfigDnsServers(data string) []dnsServer {
	var servers []dnsServer
	seen := make(map[string]bool)
	inDNSServers := false
	for _, line := range strings.Split(data, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			inDNSServers = false
			continue
		}
		lower := strings.ToLower(trimmed)
		if strings.Contains(lower, "dns servers") {
			inDNSServers = true
			if idx := strings.Index(trimmed, ":"); idx >= 0 {
				servers = appendDnsServersFromText(servers, seen, trimmed[idx+1:])
			}
			continue
		}
		if !inDNSServers {
			continue
		}
		before, _, hasColon := strings.Cut(trimmed, ":")
		if hasColon && strings.ContainsAny(before, " .\t") {
			inDNSServers = false
			continue
		}
		servers = appendDnsServersFromText(servers, seen, trimmed)
	}
	return servers
}

func parseDnsServerAddresses(data string) []dnsServer {
	var servers []dnsServer
	seen := make(map[string]bool)
	for _, line := range strings.Split(data, "\n") {
		servers = appendDnsServersFromText(servers, seen, line)
	}
	return servers
}

func appendDnsServersFromText(servers []dnsServer, seen map[string]bool, text string) []dnsServer {
	text = strings.NewReplacer(",", " ", ";", " ").Replace(text)
	for _, field := range strings.Fields(text) {
		servers = appendDnsServer(servers, seen, field)
	}
	return servers
}

func appendDnsServer(servers []dnsServer, seen map[string]bool, host string) []dnsServer {
	host = strings.TrimSpace(host)
	host = strings.Trim(host, "[]")
	host = strings.Trim(host, ",;")
	host = strings.TrimRight(host, ".")
	if host == "" {
		return servers
	}
	parseHost := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		parseHost = h
		host = h
	}
	if idx := strings.LastIndex(parseHost, "%"); idx >= 0 {
		parseHost = parseHost[:idx]
	}
	if net.ParseIP(parseHost) == nil {
		return servers
	}
	addr := net.JoinHostPort(host, "53")
	if seen[addr] {
		return servers
	}
	seen[addr] = true
	return append(servers, newDnsServer("udp", addr))
}

func newDnsServer(network, addr string) dnsServer {
	return dnsServer{
		network:         network,
		addr:            addr,
		trustedResolver: isLocalResolver(addr),
	}
}

func isLocalResolver(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if idx := strings.LastIndex(host, "%"); idx >= 0 {
		host = host[:idx]
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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

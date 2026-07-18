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
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/crypto/ssh"
)

const (
	dnsQueryTimeout = 2 * time.Second
	dnsEDNSPayload  = 4096
)

// customDnsServer records the DNS server configured via setDNS, so that SSHFP
// lookups (which the stdlib resolver can't perform) can reuse the same server.
var customDnsServer dnsServer

var dialDNS = net.DialTimeout

type dnsServer struct {
	network string
	addr    string
}

// setDNS sets the net.DefaultResolver to use the given DNS server.
func setDNS(dns string) {

	network, dns, err := resolveDnsAddress(dns)
	if err != nil {
		return

	}

	customDnsServer = newDnsServer(network, dns)

	var once sync.Once

	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, addr string) (net.Conn, error) {
			if enableDebugLogging {
				once.Do(func() {
					debug("using custom DNS: %s://%s", network, dns)
				})
			}
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

// dnssecRootTrustAnchors is the IANA DNSSEC Root Zone Trust Anchor.
// See: https://data.iana.org/root-anchors/root-anchors.xml
var dnssecRootTrustAnchors = []*dns.DS{{
	Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeDS, Class: dns.ClassINET},
	KeyTag:     20326,
	Algorithm:  dns.RSASHA256,
	DigestType: dns.SHA256,
	Digest:     "e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d"}}

var dnssecNow = time.Now
var lookupDNSSEC = queryDNSSEC

// sshfpRecord is a parsed SSHFP (DNS type 44) resource record.
type sshfpRecord struct {
	algorithm   uint8
	fpType      uint8
	fingerprint []byte
}

type dnssecValidator struct {
	dnskeyCache map[string][]*dns.DNSKEY
}

// sshfpAlgorithm maps an SSH public key type to its SSHFP algorithm number
// (RFC 4255 / RFC 6594 / RFC 7479). It returns 0 for unsupported types.
func sshfpAlgorithm(keyType string) uint8 {
	switch keyType {
	case ssh.KeyAlgoRSA, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512:
		return 1
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
func parseSSHFP(answers []dns.RR, expected string) []sshfpRecord {
	var records []sshfpRecord
	for _, answer := range answers {
		sshfp, ok := answer.(*dns.SSHFP)
		if !ok || !strings.EqualFold(sshfp.Hdr.Name, expected) {
			continue
		}
		decodedFingerprint, err := hex.DecodeString(sshfp.FingerPrint)
		if err != nil {
			debug("invalid hex in SSHFP record for %s: %v", expected, err)
			continue
		}
		records = append(records, sshfpRecord{
			algorithm: sshfp.Algorithm, fpType: sshfp.Type,
			fingerprint: decodedFingerprint,
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
// record published in DNS for the host, and returns an authentication function
// that reports whether that SSHFP RRset validates through DNSSEC. The host may
// include a port, which is stripped before the lookup. Any lookup failure is
// treated as no match. Callers must only auto-trust a match when authenticate
// returns true; an unauthenticated match merely informs the user.
func verifyHostKeyDNS(host string, key ssh.PublicKey) (found bool, matched bool, authenticate func() bool, err error) {
	name := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		name = h
	}
	if idx := strings.LastIndex(name, "%"); idx >= 0 {
		name = name[:idx]
	}
	name = strings.Trim(name, "[]")
	if name == "" || net.ParseIP(name) != nil {
		// SSHFP records are keyed by hostname; skip bare IP addresses.
		return false, false, nil, nil
	}

	records, authenticate, err := lookupSSHFP(name)
	if err != nil {
		return false, false, nil, fmt.Errorf("SSHFP lookup for '%s' failed: %v", name, err)
	}

	found = len(records) > 0
	matched = matchSSHFP(records, key)

	return found, matched, authenticate, nil
}

// lookupSSHFP queries DNS for the SSHFP (type 44) records of the given host. It
// returns an authentication function that reports success only when the SSHFP
// RRset validates through DNSSEC to the pinned root trust anchor; the response
// AD bit is never trusted.
func lookupSSHFP(host string) ([]sshfpRecord, func() bool, error) {
	name := dns.Fqdn(host)
	response, err := lookupDNSSEC(name, dns.TypeSSHFP)
	if err != nil {
		return nil, nil, err
	}
	records := parseSSHFP(response.Answer, name)
	authenticate := func() bool { return validateSSHFPDNSSEC(response, name) }
	return records, authenticate, nil
}

func queryDNSSEC(host string, rrType uint16) (*dns.Msg, error) {
	servers := dnsServers()
	if len(servers) == 0 {
		return nil, fmt.Errorf("no dns server available for DNSSEC lookup")
	}

	name := dns.Fqdn(host)

	query := new(dns.Msg)
	query.RecursionDesired = true
	query.CheckingDisabled = true
	query.SetQuestion(name, rrType)
	query.SetEdns0(dnsEDNSPayload, true)
	request, err := query.Pack()
	if err != nil {
		return nil, err
	}

	// Capture the ID assigned by SetQuestion to use for response verification.
	id := query.Id

	var lastErr error
	for _, server := range servers {
		response, err := queryDNSSECServer(server, request, id, name, rrType)
		if err != nil {
			lastErr = err
			continue
		}
		if response.Truncated && server.network == "udp" {
			tcpServer := server
			tcpServer.network = "tcp"
			if tcpResponse, err := queryDNSSECServer(tcpServer, request, id, name, rrType); err == nil {
				response = tcpResponse
			}
		}
		return response, nil
	}
	return nil, lastErr
}

func queryDNSSECServer(server dnsServer, request []byte, id uint16, name string, rrType uint16) (*dns.Msg, error) {
	conn, err := dialDNS(server.network, server.addr, dnsQueryTimeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(dnsQueryTimeout))
	if err := writeDNSMessage(conn, server.network, request); err != nil {
		return nil, err
	}
	buf, err := readDNSMessage(conn, server.network)
	if err != nil {
		return nil, err
	}
	var response dns.Msg
	if err := response.Unpack(buf); err != nil {
		return nil, err
	}
	// Reject responses that don't correspond to our query: wrong transaction
	// ID, not a response, a non-query opcode, an error rcode, or a question
	// that doesn't echo the name and type we asked for.
	if !response.Response || response.Id != id || response.Opcode != dns.OpcodeQuery || response.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("unexpected dns response")
	}
	if len(response.Question) != 1 ||
		response.Question[0].Qtype != rrType || response.Question[0].Qclass != dns.ClassINET ||
		!strings.EqualFold(response.Question[0].Name, name) {
		return nil, fmt.Errorf("dns response question mismatch")
	}
	return &response, nil
}

func validateSSHFPDNSSEC(response *dns.Msg, owner string) bool {
	rrset := dnssecRecords(response.Answer, owner, dns.TypeSSHFP)
	if len(rrset) == 0 {
		return false
	}
	sigs := rrsigRecords(response.Answer, owner, dns.TypeSSHFP)
	if len(sigs) == 0 {
		return false
	}
	validator := &dnssecValidator{dnskeyCache: make(map[string][]*dns.DNSKEY)}
	for _, sig := range sigs {
		keys, err := validator.validateDNSKEY(sig.SignerName)
		if err != nil {
			debug("DNSSEC DNSKEY validation for '%s' failed: %v", sig.SignerName, err)
			continue
		}
		if err := verifyRRSet(rrset, sig, keys); err != nil {
			debug("DNSSEC SSHFP signature validation for '%s' failed: %v", owner, err)
			continue
		}
		return true
	}
	return false
}

func (v *dnssecValidator) validateDNSKEY(zone string) ([]*dns.DNSKEY, error) {
	zone = dns.CanonicalName(zone)
	if keys, ok := v.dnskeyCache[zone]; ok {
		return keys, nil
	}

	response, err := lookupDNSSEC(zone, dns.TypeDNSKEY)
	if err != nil {
		return nil, err
	}
	rrset := dnssecRecords(response.Answer, zone, dns.TypeDNSKEY)
	keys := dnskeyRecords(rrset)
	if len(keys) == 0 {
		return nil, fmt.Errorf("no DNSKEY records for zone %q", zone)
	}
	sigs := rrsigRecords(response.Answer, zone, dns.TypeDNSKEY)
	if len(sigs) == 0 {
		return nil, fmt.Errorf("no DNSKEY RRSIG records for zone %q", zone)
	}

	var trustedDS []*dns.DS
	if zone == "." {
		trustedDS = dnssecRootTrustAnchors
	} else {
		parent := parentDNSName(zone)
		parentKeys, err := v.validateDNSKEY(parent)
		if err != nil {
			return nil, err
		}
		dsResponse, err := lookupDNSSEC(zone, dns.TypeDS)
		if err != nil {
			return nil, err
		}
		dsRRSet := dnssecRecords(dsResponse.Answer, zone, dns.TypeDS)
		for _, dsSig := range rrsigRecords(dsResponse.Answer, zone, dns.TypeDS) {
			if err := verifyRRSet(dsRRSet, dsSig, parentKeys); err != nil {
				debug("DNSSEC DS signature validation for '%s' failed: %v", zone, err)
				continue
			}
			trustedDS = dsRecords(dsRRSet)
			break
		}
		if len(trustedDS) == 0 {
			return nil, fmt.Errorf("no validated DS records for zone %q", zone)
		}
	}

	for _, key := range keys {
		if !dnskeyMatchesAnyDS(key, trustedDS) {
			continue
		}
		for _, sig := range sigs {
			if err := verifyRRSet(rrset, sig, []*dns.DNSKEY{key}); err != nil {
				debug("DNSSEC DNSKEY signature validation for '%s' failed: %v", zone, err)
				continue
			}
			v.dnskeyCache[zone] = keys
			return keys, nil
		}
	}
	return nil, fmt.Errorf("DNSKEY RRset for zone %q did not validate to trust anchor", zone)
}

func dnssecRecords(resources []dns.RR, owner string, rrType uint16) []dns.RR {
	owner = dns.CanonicalName(owner)
	var records []dns.RR
	for _, resource := range resources {
		if resource.Header().Rrtype != rrType || resource.Header().Class != dns.ClassINET {
			continue
		}
		name := dns.CanonicalName(resource.Header().Name)
		if name != owner {
			continue
		}
		records = append(records, resource)
	}
	return records
}

func dnskeyRecords(records []dns.RR) []*dns.DNSKEY {
	var keys []*dns.DNSKEY
	for _, record := range records {
		key, ok := record.(*dns.DNSKEY)
		if !ok || key.Protocol != 3 {
			continue
		}
		keys = append(keys, key)
	}
	return keys
}

func dsRecords(records []dns.RR) []*dns.DS {
	var dsRecords []*dns.DS
	for _, record := range records {
		if ds, ok := record.(*dns.DS); ok {
			dsRecords = append(dsRecords, ds)
		}
	}
	return dsRecords
}

func rrsigRecords(resources []dns.RR, owner string, covered uint16) []*dns.RRSIG {
	var sigs []*dns.RRSIG
	for _, record := range dnssecRecords(resources, owner, dns.TypeRRSIG) {
		if sig, ok := record.(*dns.RRSIG); ok && sig.TypeCovered == covered {
			sigs = append(sigs, sig)
		}
	}
	return sigs
}

func verifyRRSet(records []dns.RR, sig *dns.RRSIG, keys []*dns.DNSKEY) error {
	if len(records) == 0 {
		return fmt.Errorf("empty RRset")
	}
	now := uint32(dnssecNow().Unix())
	if now < sig.Inception || now > sig.Expiration {
		return fmt.Errorf("RRSIG validity period check failed")
	}
	for _, key := range keys {
		if key.Algorithm != sig.Algorithm || key.KeyTag() != sig.KeyTag || !strings.EqualFold(key.Hdr.Name, sig.SignerName) {
			continue
		}
		if err := sig.Verify(key, records); err == nil {
			return nil
		}
	}
	return fmt.Errorf("no DNSKEY verified RRSIG")
}

func dnskeyMatchesAnyDS(key *dns.DNSKEY, records []*dns.DS) bool {
	for _, ds := range records {
		if key.KeyTag() == ds.KeyTag && key.Algorithm == ds.Algorithm {
			if candidate := key.ToDS(ds.DigestType); candidate != nil && strings.EqualFold(candidate.Digest, ds.Digest) {
				return true
			}
		}
	}
	return false
}

func parentDNSName(name string) string {
	name = strings.TrimSuffix(dns.CanonicalName(name), ".")
	if name == "" {
		return "."
	}
	parts := strings.Split(name, ".")
	if len(parts) <= 1 {
		return "."
	}
	return strings.Join(parts[1:], ".") + "."
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
	for line := range strings.SplitSeq(data, "\n") {
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
	for line := range strings.SplitSeq(data, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "nameserver[") {
			continue
		}
		if _, after, ok := strings.Cut(line, ":"); ok {
			servers = appendDnsServer(servers, seen, after)
		}
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

	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	if _, err := netip.ParseAddr(host); err != nil {
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
		network: network,
		addr:    addr,
	}
}

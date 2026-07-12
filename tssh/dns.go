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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	dnsQueryTimeout = 2 * time.Second
	dnsOpCodeQuery  = dnsmessage.OpCode(0)
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

const (
	dnsTypeDS     = dnsmessage.Type(43)
	dnsTypeSSHFP  = dnsmessage.Type(44)
	dnsTypeRRSIG  = dnsmessage.Type(46)
	dnsTypeDNSKEY = dnsmessage.Type(48)
)

const (
	dnssecAlgorithmRSASHA1         = 5
	dnssecAlgorithmRSASHA1NSEC3    = 7
	dnssecAlgorithmRSASHA256       = 8
	dnssecAlgorithmRSASHA512       = 10
	dnssecAlgorithmECDSAP256SHA256 = 13
	dnssecAlgorithmECDSAP384SHA384 = 14
	dnssecAlgorithmED25519         = 15
)

const (
	dnssecDigestSHA1   = 1
	dnssecDigestSHA256 = 2
	dnssecDigestSHA384 = 4
)

var dnssecRootTrustAnchors = []dsRecord{
	{
		dnssecRecord: dnssecRecord{name: ".", rrType: dnsTypeDS, class: dnsmessage.ClassINET},
		keyTag:       20326,
		algorithm:    8,
		digestType:   dnssecDigestSHA256,
		digest:       mustDecodeHex("e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d"),
	},
}

var dnssecNow = time.Now
var lookupDNSSEC = queryDNSSEC

// sshfpRecord is a parsed SSHFP (DNS type 44) resource record.
type sshfpRecord struct {
	algorithm   uint8
	fpType      uint8
	fingerprint []byte
}

type dnssecRecord struct {
	name   string
	rrType dnsmessage.Type
	class  dnsmessage.Class
	ttl    uint32
	rdata  []byte
}

type dnskeyRecord struct {
	dnssecRecord
	flags     uint16
	protocol  uint8
	algorithm uint8
	publicKey []byte
	keyTag    uint16
}

type dsRecord struct {
	dnssecRecord
	keyTag     uint16
	algorithm  uint8
	digestType uint8
	digest     []byte
}

type rrsigRecord struct {
	dnssecRecord
	typeCovered dnsmessage.Type
	algorithm   uint8
	labels      uint8
	originalTTL uint32
	expiration  uint32
	inception   uint32
	keyTag      uint16
	signerName  string
	signature   []byte
}

type dnssecValidator struct {
	dnskeyCache map[string][]dnskeyRecord
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
func parseSSHFP(answers []dnsmessage.Resource, expected dnsmessage.Name) []sshfpRecord {
	var records []sshfpRecord
	for _, answer := range answers {
		if answer.Header.Type != dnsTypeSSHFP {
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
	name, err := dnsmessage.NewName(dnsName(host))
	if err != nil {
		return nil, nil, err
	}
	response, err := lookupDNSSEC(name.String(), dnsTypeSSHFP)
	if err != nil {
		return nil, nil, err
	}
	records := parseSSHFP(response.Answers, name)
	authenticate := func() bool { return validateSSHFPDNSSEC(response, name) }
	return records, authenticate, nil
}

func queryDNSSEC(host string, rrType dnsmessage.Type) (*dnsmessage.Message, error) {
	servers := dnsServers()
	if len(servers) == 0 {
		return nil, fmt.Errorf("no dns server available for DNSSEC lookup")
	}

	name, err := dnsmessage.NewName(dnsName(host))
	if err != nil {
		return nil, err
	}

	// Use a random transaction ID so an off-path attacker cannot trivially
	// forge a matching UDP response.
	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return nil, err
	}
	id := binary.BigEndian.Uint16(idBytes[:])

	optHeader := dnsmessage.ResourceHeader{}
	if err := optHeader.SetEDNS0(dnsEDNSPayload, dnsmessage.RCodeSuccess, true); err != nil {
		return nil, err
	}
	query := dnsmessage.Message{
		Header: dnsmessage.Header{ID: id, RecursionDesired: true, CheckingDisabled: true},
		Questions: []dnsmessage.Question{{
			Name:  name,
			Type:  rrType,
			Class: dnsmessage.ClassINET,
		}},
		Additionals: []dnsmessage.Resource{{
			Header: optHeader,
			Body:   &dnsmessage.OPTResource{},
		}},
	}
	request, err := query.Pack()
	if err != nil {
		return nil, err
	}

	var lastErr error
	for _, server := range servers {
		response, err := queryDNSSECServer(server, request, id, name, rrType)
		if err != nil {
			lastErr = err
			continue
		}
		if response.Header.Truncated && server.network == "udp" {
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

func querySSHFP(server dnsServer, request []byte, id uint16, name dnsmessage.Name) ([]sshfpRecord, bool, error) {
	response, err := queryDNSSECServer(server, request, id, name, dnsTypeSSHFP)
	if err != nil {
		return nil, false, err
	}
	return parseSSHFP(response.Answers, name), validateSSHFPDNSSEC(response, name), nil
}

func queryDNSSECServer(server dnsServer, request []byte, id uint16, name dnsmessage.Name, rrType dnsmessage.Type) (*dnsmessage.Message, error) {
	conn, err := dialDNS(server.network, server.addr, dnsQueryTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(dnsQueryTimeout))
	if err := writeDNSMessage(conn, server.network, request); err != nil {
		return nil, err
	}
	buf, err := readDNSMessage(conn, server.network)
	if err != nil {
		return nil, err
	}
	var response dnsmessage.Message
	if err := response.Unpack(buf); err != nil {
		return nil, err
	}
	// Reject responses that don't correspond to our query: wrong transaction
	// ID, not a response, a non-query opcode, an error rcode, or a question
	// that doesn't echo the name and type we asked for.
	if !response.Header.Response ||
		response.Header.ID != id ||
		response.Header.OpCode != dnsOpCodeQuery ||
		response.Header.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("unexpected dns response")
	}
	if len(response.Questions) != 1 ||
		response.Questions[0].Type != rrType ||
		response.Questions[0].Class != dnsmessage.ClassINET ||
		!strings.EqualFold(response.Questions[0].Name.String(), name.String()) {
		return nil, fmt.Errorf("dns response question mismatch")
	}
	return &response, nil
}

func validateSSHFPDNSSEC(response *dnsmessage.Message, owner dnsmessage.Name) bool {
	rrset := dnssecRecords(response.Answers, owner.String(), dnsTypeSSHFP)
	if len(rrset) == 0 {
		return false
	}
	sigs := rrsigRecords(response.Answers, owner.String(), dnsTypeSSHFP)
	if len(sigs) == 0 {
		return false
	}
	validator := &dnssecValidator{dnskeyCache: make(map[string][]dnskeyRecord)}
	for _, sig := range sigs {
		keys, err := validator.validateDNSKEY(sig.signerName)
		if err != nil {
			debug("DNSSEC DNSKEY validation for '%s' failed: %v", sig.signerName, err)
			continue
		}
		if err := verifyRRSet(rrset, sig, keys); err != nil {
			debug("DNSSEC SSHFP signature validation for '%s' failed: %v", owner.String(), err)
			continue
		}
		return true
	}
	return false
}

func (v *dnssecValidator) validateDNSKEY(zone string) ([]dnskeyRecord, error) {
	zone = canonicalDNSName(zone)
	if keys, ok := v.dnskeyCache[zone]; ok {
		return keys, nil
	}

	response, err := lookupDNSSEC(zone, dnsTypeDNSKEY)
	if err != nil {
		return nil, err
	}
	rrset := dnssecRecords(response.Answers, zone, dnsTypeDNSKEY)
	keys := dnskeyRecords(rrset)
	if len(keys) == 0 {
		return nil, fmt.Errorf("no DNSKEY records for %s", zone)
	}
	sigs := rrsigRecords(response.Answers, zone, dnsTypeDNSKEY)
	if len(sigs) == 0 {
		return nil, fmt.Errorf("no DNSKEY RRSIG records for %s", zone)
	}

	var trustedDS []dsRecord
	if zone == "." {
		trustedDS = dnssecRootTrustAnchors
	} else {
		parent := parentDNSName(zone)
		parentKeys, err := v.validateDNSKEY(parent)
		if err != nil {
			return nil, err
		}
		dsResponse, err := lookupDNSSEC(zone, dnsTypeDS)
		if err != nil {
			return nil, err
		}
		dsRRSet := dnssecRecords(dsResponse.Answers, zone, dnsTypeDS)
		for _, dsSig := range rrsigRecords(dsResponse.Answers, zone, dnsTypeDS) {
			if err := verifyRRSet(dsRRSet, dsSig, parentKeys); err != nil {
				debug("DNSSEC DS signature validation for '%s' failed: %v", zone, err)
				continue
			}
			trustedDS = dsRecords(dsRRSet)
			break
		}
		if len(trustedDS) == 0 {
			return nil, fmt.Errorf("no validated DS records for %s", zone)
		}
	}

	for _, key := range keys {
		if !dnskeyMatchesAnyDS(zone, key, trustedDS) {
			continue
		}
		for _, sig := range sigs {
			if err := verifyRRSet(rrset, sig, []dnskeyRecord{key}); err != nil {
				debug("DNSSEC DNSKEY signature validation for '%s' failed: %v", zone, err)
				continue
			}
			v.dnskeyCache[zone] = keys
			return keys, nil
		}
	}
	return nil, fmt.Errorf("DNSKEY RRset for %s did not validate to trust anchor", zone)
}

func dnssecRecords(resources []dnsmessage.Resource, owner string, rrType dnsmessage.Type) []dnssecRecord {
	owner = canonicalDNSName(owner)
	var records []dnssecRecord
	for _, resource := range resources {
		if resource.Header.Type != rrType || resource.Header.Class != dnsmessage.ClassINET {
			continue
		}
		name := canonicalDNSName(resource.Header.Name.String())
		if !strings.EqualFold(name, owner) {
			continue
		}
		unknown, ok := resource.Body.(*dnsmessage.UnknownResource)
		if !ok {
			continue
		}
		records = append(records, dnssecRecord{
			name:   name,
			rrType: resource.Header.Type,
			class:  resource.Header.Class,
			ttl:    resource.Header.TTL,
			rdata:  append([]byte(nil), unknown.Data...),
		})
	}
	return records
}

func dnskeyRecords(records []dnssecRecord) []dnskeyRecord {
	var keys []dnskeyRecord
	for _, record := range records {
		if len(record.rdata) < 4 {
			continue
		}
		key := dnskeyRecord{
			dnssecRecord: record,
			flags:        binary.BigEndian.Uint16(record.rdata[0:2]),
			protocol:     record.rdata[2],
			algorithm:    record.rdata[3],
			publicKey:    append([]byte(nil), record.rdata[4:]...),
			keyTag:       dnskeyTag(record.rdata),
		}
		if key.protocol != 3 {
			continue
		}
		keys = append(keys, key)
	}
	return keys
}

func dsRecords(records []dnssecRecord) []dsRecord {
	var dsRecords []dsRecord
	for _, record := range records {
		if len(record.rdata) < 4 {
			continue
		}
		dsRecords = append(dsRecords, dsRecord{
			dnssecRecord: record,
			keyTag:       binary.BigEndian.Uint16(record.rdata[0:2]),
			algorithm:    record.rdata[2],
			digestType:   record.rdata[3],
			digest:       append([]byte(nil), record.rdata[4:]...),
		})
	}
	return dsRecords
}

func rrsigRecords(resources []dnsmessage.Resource, owner string, covered dnsmessage.Type) []rrsigRecord {
	var sigs []rrsigRecord
	for _, record := range dnssecRecords(resources, owner, dnsTypeRRSIG) {
		sig, ok := parseRRSIG(record)
		if !ok || sig.typeCovered != covered {
			continue
		}
		sigs = append(sigs, sig)
	}
	return sigs
}

func parseRRSIG(record dnssecRecord) (rrsigRecord, bool) {
	if len(record.rdata) < 18 {
		return rrsigRecord{}, false
	}
	signerName, off, ok := unpackDNSName(record.rdata, 18)
	if !ok || off > len(record.rdata) {
		return rrsigRecord{}, false
	}
	return rrsigRecord{
		dnssecRecord: record,
		typeCovered:  dnsmessage.Type(binary.BigEndian.Uint16(record.rdata[0:2])),
		algorithm:    record.rdata[2],
		labels:       record.rdata[3],
		originalTTL:  binary.BigEndian.Uint32(record.rdata[4:8]),
		expiration:   binary.BigEndian.Uint32(record.rdata[8:12]),
		inception:    binary.BigEndian.Uint32(record.rdata[12:16]),
		keyTag:       binary.BigEndian.Uint16(record.rdata[16:18]),
		signerName:   signerName,
		signature:    append([]byte(nil), record.rdata[off:]...),
	}, true
}

func verifyRRSet(records []dnssecRecord, sig rrsigRecord, keys []dnskeyRecord) error {
	if len(records) == 0 {
		return fmt.Errorf("empty RRset")
	}
	now := uint32(dnssecNow().Unix())
	if now < sig.inception || now > sig.expiration {
		return fmt.Errorf("RRSIG validity period check failed")
	}
	signedData, err := rrsetSignedData(records, sig)
	if err != nil {
		return err
	}
	for _, key := range keys {
		if key.algorithm != sig.algorithm || key.keyTag != sig.keyTag {
			continue
		}
		if !strings.EqualFold(key.name, sig.signerName) {
			continue
		}
		if err := verifyDNSSECSignature(key, sig.signature, signedData); err == nil {
			return nil
		}
	}
	return fmt.Errorf("no DNSKEY verified RRSIG")
}

func rrsetSignedData(records []dnssecRecord, sig rrsigRecord) ([]byte, error) {
	var data []byte
	data = appendUint16(data, uint16(sig.typeCovered))
	data = append(data, sig.algorithm, sig.labels)
	data = appendUint32(data, sig.originalTTL)
	data = appendUint32(data, sig.expiration)
	data = appendUint32(data, sig.inception)
	data = appendUint16(data, sig.keyTag)
	signerName, err := packDNSName(sig.signerName)
	if err != nil {
		return nil, err
	}
	data = append(data, signerName...)

	sort.Slice(records, func(i, j int) bool {
		return bytes.Compare(records[i].rdata, records[j].rdata) < 0
	})

	for _, record := range records {
		if record.rrType != sig.typeCovered {
			return nil, fmt.Errorf("RRSIG type does not match RRset")
		}
		if !rrsigSignerCovers(record.name, sig) {
			return nil, fmt.Errorf("RRSIG signer does not cover RRset owner")
		}
		if int(sig.labels) > dnsLabelCount(record.name) {
			return nil, fmt.Errorf("RRSIG label count exceeds owner name")
		}
		owner, err := packDNSName(rrsigOwnerName(record.name, sig.labels))
		if err != nil {
			return nil, err
		}

		data = append(data, owner...)
		data = appendUint16(data, uint16(record.rrType))
		data = appendUint16(data, uint16(record.class))
		data = appendUint32(data, sig.originalTTL)
		data = appendUint16(data, uint16(len(record.rdata)))
		data = append(data, record.rdata...)
	}

	return data, nil
}

func verifyDNSSECSignature(key dnskeyRecord, signature, data []byte) error {
	switch key.algorithm {
	case dnssecAlgorithmRSASHA1, dnssecAlgorithmRSASHA1NSEC3:
		pub, err := parseRSADNSKEY(key.publicKey)
		if err != nil {
			return err
		}
		sum := sha1.Sum(data)
		return rsa.VerifyPKCS1v15(pub, crypto.SHA1, sum[:], signature)
	case dnssecAlgorithmRSASHA256:
		pub, err := parseRSADNSKEY(key.publicKey)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], signature)
	case dnssecAlgorithmRSASHA512:
		pub, err := parseRSADNSKEY(key.publicKey)
		if err != nil {
			return err
		}
		sum := sha512.Sum512(data)
		return rsa.VerifyPKCS1v15(pub, crypto.SHA512, sum[:], signature)
	case dnssecAlgorithmECDSAP256SHA256:
		pub, err := parseECDSADNSKEY(key.publicKey, elliptic.P256(), 32)
		if err != nil {
			return err
		}
		if len(signature) != 64 {
			return fmt.Errorf("invalid ECDSA P-256 signature length")
		}
		sum := sha256.Sum256(data)
		if ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
			return nil
		}
	case dnssecAlgorithmECDSAP384SHA384:
		pub, err := parseECDSADNSKEY(key.publicKey, elliptic.P384(), 48)
		if err != nil {
			return err
		}
		if len(signature) != 96 {
			return fmt.Errorf("invalid ECDSA P-384 signature length")
		}
		sum := sha512.Sum384(data)
		if ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(signature[:48]), new(big.Int).SetBytes(signature[48:])) {
			return nil
		}
	case dnssecAlgorithmED25519:
		if len(key.publicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("invalid Ed25519 public key length")
		}
		if ed25519.Verify(ed25519.PublicKey(key.publicKey), data, signature) {
			return nil
		}
	default:
		return fmt.Errorf("unsupported DNSSEC algorithm %d", key.algorithm)
	}
	return fmt.Errorf("DNSSEC signature verification failed")
}

func parseRSADNSKEY(data []byte) (*rsa.PublicKey, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("invalid RSA DNSKEY")
	}
	exponentLength := int(data[0])
	off := 1
	if exponentLength == 0 {
		if len(data) < 3 {
			return nil, fmt.Errorf("invalid RSA DNSKEY exponent length")
		}
		exponentLength = int(binary.BigEndian.Uint16(data[1:3]))
		off = 3
	}
	if exponentLength == 0 || off+exponentLength >= len(data) {
		return nil, fmt.Errorf("invalid RSA DNSKEY length")
	}
	exponent := new(big.Int).SetBytes(data[off : off+exponentLength])
	modulus := new(big.Int).SetBytes(data[off+exponentLength:])
	if !exponent.IsInt64() {
		return nil, fmt.Errorf("invalid RSA DNSKEY exponent")
	}
	return &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}, nil
}

func parseECDSADNSKEY(data []byte, curve elliptic.Curve, size int) (*ecdsa.PublicKey, error) {
	if len(data) != size*2 {
		return nil, fmt.Errorf("invalid ECDSA DNSKEY length")
	}
	x := new(big.Int).SetBytes(data[:size])
	y := new(big.Int).SetBytes(data[size:])
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("invalid ECDSA DNSKEY point")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func dnskeyMatchesAnyDS(owner string, key dnskeyRecord, records []dsRecord) bool {
	for _, ds := range records {
		if key.keyTag != ds.keyTag || key.algorithm != ds.algorithm {
			continue
		}
		digest, ok := dnskeyDigest(owner, key, ds.digestType)
		if !ok {
			continue
		}
		if bytes.Equal(digest, ds.digest) {
			return true
		}
	}
	return false
}

func dnskeyDigest(owner string, key dnskeyRecord, digestType uint8) ([]byte, bool) {
	ownerWire, err := packDNSName(owner)
	if err != nil {
		return nil, false
	}
	data := append(ownerWire, key.rdata...)
	switch digestType {
	case dnssecDigestSHA1:
		sum := sha1.Sum(data)
		return sum[:], true
	case dnssecDigestSHA256:
		sum := sha256.Sum256(data)
		return sum[:], true
	case dnssecDigestSHA384:
		sum := sha512.Sum384(data)
		return sum[:], true
	default:
		return nil, false
	}
}

func dnskeyTag(rdata []byte) uint16 {
	var ac uint32
	for i, b := range rdata {
		if i&1 == 0 {
			ac += uint32(b) << 8
		} else {
			ac += uint32(b)
		}
	}
	ac += (ac >> 16) & 0xffff
	return uint16(ac & 0xffff)
}

func rrsigOwnerName(owner string, labels uint8) string {
	parts := dnsLabels(owner)
	if len(parts) > int(labels) {
		if labels == 0 {
			return "."
		}
		return "*." + strings.Join(parts[len(parts)-int(labels):], ".") + "."
	}
	return canonicalDNSName(owner)
}

func rrsigSignerCovers(owner string, sig rrsigRecord) bool {
	owner = canonicalDNSName(owner)
	signer := canonicalDNSName(sig.signerName)
	switch sig.typeCovered {
	case dnsTypeDNSKEY:
		return owner == signer
	case dnsTypeDS:
		return parentDNSName(owner) == signer
	default:
		if signer == "." {
			return owner == "."
		}
		return owner == signer || strings.HasSuffix(owner, "."+signer)
	}
}

func parentDNSName(name string) string {
	parts := dnsLabels(name)
	if len(parts) <= 1 {
		return "."
	}
	return strings.Join(parts[1:], ".") + "."
}

func dnsLabelCount(name string) int {
	return len(dnsLabels(name))
}

func dnsLabels(name string) []string {
	name = strings.TrimSuffix(canonicalDNSName(name), ".")
	if name == "" {
		return nil
	}
	return strings.Split(name, ".")
}

func canonicalDNSName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" || name == "." {
		return "."
	}
	name = strings.Trim(name, "[]")
	name = strings.TrimSuffix(name, ".") + "."
	return strings.ToLower(name)
}

func packDNSName(name string) ([]byte, error) {
	name = canonicalDNSName(name)
	if name == "." {
		return []byte{0}, nil
	}
	var wire []byte
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("invalid DNS name %s", name)
		}
		wire = append(wire, byte(len(label)))
		wire = append(wire, label...)
	}
	return append(wire, 0), nil
}

func unpackDNSName(data []byte, off int) (string, int, bool) {
	var labels []string
	for {
		if off >= len(data) {
			return "", off, false
		}
		length := int(data[off])
		off++
		if length == 0 {
			if len(labels) == 0 {
				return ".", off, true
			}
			return strings.ToLower(strings.Join(labels, ".")) + ".", off, true
		}
		if length&0xc0 != 0 || off+length > len(data) {
			return "", off, false
		}
		labels = append(labels, string(data[off:off+length]))
		off += length
	}
}

func appendUint16(data []byte, value uint16) []byte {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], value)
	return append(data, buf[:]...)
}

func appendUint32(data []byte, value uint32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], value)
	return append(data, buf[:]...)
}

func mustDecodeHex(value string) []byte {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return decoded
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
		network: network,
		addr:    addr,
	}
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

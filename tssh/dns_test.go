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
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
)

func TestDNS(t *testing.T) {
	for input, want := range map[string]string{
		"8.8.8.8": "udp://8.8.8.8:53", "tcp://8.8.8.8": "tcp://8.8.8.8:53", "udp://[2001:4860:4860::8888]:5300": "udp://[2001:4860:4860::8888]:5300",
	} {
		network, address, err := resolveDnsAddress(input)
		assert.NoError(t, err)
		assert.Equal(t, want, fmt.Sprintf("%s://%s", network, address))
	}
}

func TestSSHFPAlgorithm(t *testing.T) {
	assert.Equal(t, uint8(1), sshfpAlgorithm(ssh.KeyAlgoRSA))
	assert.Equal(t, uint8(3), sshfpAlgorithm(ssh.KeyAlgoECDSA256))
	assert.Equal(t, uint8(4), sshfpAlgorithm(ssh.KeyAlgoED25519))
	assert.Zero(t, sshfpAlgorithm("ssh-unknown"))
}

func TestMatchSSHFP(t *testing.T) {
	key := testSSHKey(t)
	sum := sha256.Sum256(key.Marshal())
	assert.True(t, matchSSHFP([]sshfpRecord{{algorithm: 4, fpType: sshfpTypeSHA256, fingerprint: sum[:]}}, key))
	assert.False(t, matchSSHFP([]sshfpRecord{{algorithm: 1, fpType: sshfpTypeSHA256, fingerprint: sum[:]}}, key))
}

func TestParseSystemDNSServers(t *testing.T) {
	assert.Equal(t, []dnsServer{{network: "udp", addr: "127.0.0.53:53"}, {network: "udp", addr: "[2001:4860:4860::8888]:53"}}, parseResolvConfDnsServers("nameserver 127.0.0.53\nnameserver 2001:4860:4860::8888\n"))
}

func TestParseSSHFP(t *testing.T) {
	records := parseSSHFP([]dns.RR{
		&dns.SSHFP{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSSHFP, Class: dns.ClassINET}, Algorithm: 4, Type: 2, FingerPrint: "aabbcc"},
		&dns.SSHFP{Hdr: dns.RR_Header{Name: "evil.example.com.", Rrtype: dns.TypeSSHFP, Class: dns.ClassINET}, Algorithm: 4, Type: 2, FingerPrint: "aabbcc"},
	}, "example.com.")
	assert.Equal(t, []sshfpRecord{{algorithm: 4, fpType: 2, fingerprint: []byte{0xaa, 0xbb, 0xcc}}}, records)
}

func querySSHFP(server dnsServer, request []byte, id uint16, name string) ([]sshfpRecord, bool, error) {
	response, err := queryDNSSECServer(server, request, id, name, dns.TypeSSHFP)
	if err != nil {
		return nil, false, err
	}
	return parseSSHFP(response.Answer, name), validateSSHFPDNSSEC(response, name), nil
}

func TestQuerySSHFPRejectsNonQueryOpcode(t *testing.T) {
	name, request := testSSHFPQuery(t)
	response := testSSHFPResponse(t, 0x1234, name, dns.OpcodeStatus, false)
	done := mockDNSDialer(t, "udp", response)
	_, _, err := querySSHFP(dnsServer{network: "udp", addr: "dns.test:53"}, request, 0x1234, name)
	assert.ErrorContains(t, err, "unexpected dns response")
	assert.NoError(t, waitDNSServer(t, done))
}

func TestQuerySSHFPTCPHonorsNetwork(t *testing.T) {
	name, request := testSSHFPQuery(t)
	done := mockDNSDialer(t, "tcp", testSSHFPResponse(t, 0x1234, name, dns.OpcodeQuery, true))
	records, authenticated, err := querySSHFP(dnsServer{network: "tcp", addr: "dns.test:53"}, request, 0x1234, name)
	assert.NoError(t, err)
	assert.Len(t, records, 1)
	assert.False(t, authenticated)
	assert.NoError(t, waitDNSServer(t, done))
}

func TestVerifyHostKeyDNSValidatedChainAccepts(t *testing.T) {
	key := testSSHKey(t)
	responses, anchors := testDNSSECChain(t, "host.example.test.", key, false)
	withDNSSECTestLookup(t, responses, anchors)
	found, matched, authenticate, err := verifyHostKeyDNS("host.example.test:22", key)
	assert.NoError(t, err)
	assert.True(t, found)
	assert.True(t, matched)
	assert.True(t, authenticate())
}

func TestLookupSSHFPADBitOnlyDoesNotAuthenticate(t *testing.T) {
	key := testSSHKey(t)
	msg := testSSHFPOnlyResponse("host.example.test.", key, true)
	withDNSSECTestLookup(t, map[string]*dns.Msg{testLookupKey("host.example.test.", dns.TypeSSHFP): msg}, nil)
	_, matched, authenticate, err := verifyHostKeyDNS("host.example.test", key)
	assert.NoError(t, err)
	assert.True(t, matched)
	assert.False(t, authenticate())
}

func TestLookupSSHFPRejectsTamperedRRSIG(t *testing.T) {
	key := testSSHKey(t)
	responses, anchors := testDNSSECChain(t, "host.example.test.", key, true)
	withDNSSECTestLookup(t, responses, anchors)
	_, matched, authenticate, err := verifyHostKeyDNS("host.example.test", key)
	assert.NoError(t, err)
	assert.True(t, matched)
	assert.False(t, authenticate())
}

func TestCompressedRRSIGSignerNameValidates(t *testing.T) {
	key := testSSHKey(t)
	responses, anchors := testDNSSECChain(t, "host.example.test.", key, false)
	responses[testLookupKey("host.example.test.", dns.TypeSSHFP)].Compress = true
	packed, err := responses[testLookupKey("host.example.test.", dns.TypeSSHFP)].Pack()
	assert.NoError(t, err)
	var unpacked dns.Msg
	assert.NoError(t, unpacked.Unpack(packed))
	responses[testLookupKey("host.example.test.", dns.TypeSSHFP)] = &unpacked
	withDNSSECTestLookup(t, responses, anchors)
	_, _, authenticate, err := verifyHostKeyDNS("host.example.test", key)
	assert.NoError(t, err)
	assert.True(t, authenticate())
}

func TestAppendDnsServerIPv6Zone(t *testing.T) {
	servers := appendDnsServer(
		nil,
		map[string]bool{},
		"fe80::1%12",
	)

	assert.Equal(t, []dnsServer{
		{
			network: "udp",
			addr:    "[fe80::1%12]:53",
		},
	}, servers)
}

func testSSHKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	assert.NoError(t, err)
	key, err := ssh.NewPublicKey(pub)
	assert.NoError(t, err)
	return key
}

func testSSHFPQuery(t *testing.T) (string, []byte) {
	t.Helper()
	msg := new(dns.Msg)
	msg.Id = 0x1234
	msg.SetQuestion("example.com.", dns.TypeSSHFP)
	msg.SetEdns0(dnsEDNSPayload, true)
	packed, err := msg.Pack()
	assert.NoError(t, err)
	return "example.com.", packed
}

func testSSHFPResponse(t *testing.T, id uint16, name string, opcode int, authenticated bool) []byte {
	t.Helper()
	msg := &dns.Msg{MsgHdr: dns.MsgHdr{Id: id, Response: true, Opcode: opcode, AuthenticatedData: authenticated}, Question: []dns.Question{{Name: name, Qtype: dns.TypeSSHFP, Qclass: dns.ClassINET}}, Answer: []dns.RR{&dns.SSHFP{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeSSHFP, Class: dns.ClassINET}, Algorithm: 4, Type: 2, FingerPrint: "aabb"}}}
	packed, err := msg.Pack()
	assert.NoError(t, err)
	return packed
}

func testDNSSECChain(t *testing.T, host string, key ssh.PublicKey, tamper bool) (map[string]*dns.Msg, []*dns.DS) {
	t.Helper()
	rootPub, rootPriv, _ := ed25519.GenerateKey(nil)
	tldPub, tldPriv, _ := ed25519.GenerateKey(nil)
	zonePub, zonePriv, _ := ed25519.GenerateKey(nil)
	rootKey := testDNSKEY(".", rootPub)
	tldKey := testDNSKEY("test.", tldPub)
	zoneKey := testDNSKEY("example.test.", zonePub)
	sshfp := testSSHFP(host, key)
	sshfpResponse := testSignedResponse(t, host, dns.TypeSSHFP, []dns.RR{sshfp}, zoneKey, zonePriv)
	if tamper {
		sshfpResponse.Answer[len(sshfpResponse.Answer)-1].(*dns.RRSIG).Signature = "AAAA"
	}
	return map[string]*dns.Msg{
		testLookupKey(host, dns.TypeSSHFP):             sshfpResponse,
		testLookupKey("example.test.", dns.TypeDNSKEY): testSignedResponse(t, "example.test.", dns.TypeDNSKEY, []dns.RR{zoneKey}, zoneKey, zonePriv),
		testLookupKey("example.test.", dns.TypeDS):     testSignedResponse(t, "example.test.", dns.TypeDS, []dns.RR{zoneKey.ToDS(dns.SHA256)}, tldKey, tldPriv),
		testLookupKey("test.", dns.TypeDNSKEY):         testSignedResponse(t, "test.", dns.TypeDNSKEY, []dns.RR{tldKey}, tldKey, tldPriv),
		testLookupKey("test.", dns.TypeDS):             testSignedResponse(t, "test.", dns.TypeDS, []dns.RR{tldKey.ToDS(dns.SHA256)}, rootKey, rootPriv),
		testLookupKey(".", dns.TypeDNSKEY):             testSignedResponse(t, ".", dns.TypeDNSKEY, []dns.RR{rootKey}, rootKey, rootPriv),
	}, []*dns.DS{rootKey.ToDS(dns.SHA256)}
}

func testDNSKEY(name string, publicKey ed25519.PublicKey) *dns.DNSKEY {
	return &dns.DNSKEY{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600}, Flags: 257, Protocol: 3, Algorithm: dns.ED25519, PublicKey: base64.StdEncoding.EncodeToString(publicKey)}
}

func testSSHFP(name string, key ssh.PublicKey) *dns.SSHFP {
	sum := sha256.Sum256(key.Marshal())
	return &dns.SSHFP{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeSSHFP, Class: dns.ClassINET, Ttl: 3600}, Algorithm: sshfpAlgorithm(key.Type()), Type: dns.SHA256, FingerPrint: fmt.Sprintf("%x", sum)}
}

func testSSHFPOnlyResponse(name string, key ssh.PublicKey, ad bool) *dns.Msg {
	return &dns.Msg{MsgHdr: dns.MsgHdr{Response: true, AuthenticatedData: ad}, Question: []dns.Question{{Name: name, Qtype: dns.TypeSSHFP, Qclass: dns.ClassINET}}, Answer: []dns.RR{testSSHFP(name, key)}}
}

func testSignedResponse(t *testing.T, owner string, rrtype uint16, records []dns.RR, signer *dns.DNSKEY, private ed25519.PrivateKey) *dns.Msg {
	t.Helper()
	now := uint32(time.Now().Unix())
	sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600}, TypeCovered: rrtype, Algorithm: signer.Algorithm, Labels: uint8(dns.CountLabel(owner)), OrigTtl: 3600, Expiration: now + 3600, Inception: now - 3600, KeyTag: signer.KeyTag(), SignerName: signer.Hdr.Name}
	assert.NoError(t, sig.Sign(private, records))
	return &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}, Question: []dns.Question{{Name: owner, Qtype: rrtype, Qclass: dns.ClassINET}}, Answer: append(records, sig)}
}

func withDNSSECTestLookup(t *testing.T, responses map[string]*dns.Msg, anchors []*dns.DS) {
	t.Helper()
	oldLookup, oldAnchors, oldNow := lookupDNSSEC, dnssecRootTrustAnchors, dnssecNow
	lookupDNSSEC = func(name string, rrtype uint16) (*dns.Msg, error) {
		if response := responses[testLookupKey(name, rrtype)]; response != nil {
			return response, nil
		}
		return nil, fmt.Errorf("missing test DNS response")
	}
	if anchors != nil {
		dnssecRootTrustAnchors = anchors
	}
	dnssecNow = time.Now
	t.Cleanup(func() { lookupDNSSEC, dnssecRootTrustAnchors, dnssecNow = oldLookup, oldAnchors, oldNow })
}

func testLookupKey(name string, rrtype uint16) string {
	return fmt.Sprintf("%s/%d", dns.CanonicalName(name), rrtype)
}

func mockDNSDialer(t *testing.T, expectedNetwork string, response []byte) <-chan error {
	t.Helper()
	old := dialDNS
	done := make(chan error, 1)
	dialDNS = func(network, _ string, _ time.Duration) (net.Conn, error) {
		if network != expectedNetwork {
			return nil, fmt.Errorf("expected %s DNS network, got %s", expectedNetwork, network)
		}
		client, server := net.Pipe()
		go func() {
			defer func() { _ = server.Close() }()
			if network == "tcp" {
				done <- serveTCP(server, response)
			} else {
				done <- serveUDP(server, response)
			}
		}()
		return client, nil
	}
	t.Cleanup(func() { dialDNS = old })
	return done
}
func serveUDP(c net.Conn, response []byte) error {
	buf := make([]byte, 4096)
	if _, err := c.Read(buf); err != nil {
		return err
	}
	_, err := c.Write(response)
	return err
}
func serveTCP(c net.Conn, response []byte) error {
	var size [2]byte
	if _, err := io.ReadFull(c, size[:]); err != nil {
		return err
	}
	request := make([]byte, int(size[0])<<8|int(size[1]))
	if _, err := io.ReadFull(c, request); err != nil {
		return err
	}
	reply := append([]byte{byte(len(response) >> 8), byte(len(response))}, response...)
	_, err := c.Write(reply)
	return err
}
func waitDNSServer(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(time.Second):
		t.Fatal("dns test server did not finish")
		return nil
	}
}

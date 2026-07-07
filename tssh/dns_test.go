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
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/dns/dnsmessage"
)

func TestDNS(t *testing.T) {
	enableWarning := enableWarningLogging
	enableWarningLogging = false
	defer func() { enableWarningLogging = enableWarning }()

	assert := assert.New(t)
	assertDestEqual := func(waitParseDns, expectedDns string) {

		t.Helper()
		network, dns, err := resolveDnsAddress(waitParseDns)
		assert.Nil(err)
		assert.Equal(expectedDns, fmt.Sprintf("%s://%s", network, dns))

	}

	assertDestNotNil := func(preParseDns string) {
		t.Helper()
		_, _, err := resolveDnsAddress(preParseDns)
		assert.NotNil(err)

	}

	assertDestNotNil("ab cd")
	assertDestNotNil("udp://ab:cd")

	assertDestEqual("8.8.8.8", "udp://8.8.8.8:53")
	assertDestEqual("8.8.8.8:53", "udp://8.8.8.8:53")
	assertDestEqual("udp://8.8.8.8", "udp://8.8.8.8:53")
	assertDestEqual("udp://8.8.8.8:53", "udp://8.8.8.8:53")
	assertDestEqual("tcp://8.8.8.8", "tcp://8.8.8.8:53")
	assertDestEqual("tcp://8.8.8.8:53", "tcp://8.8.8.8:53")
	assertDestEqual("udp://8.8.8.8:5300", "udp://8.8.8.8:5300")

	assertDestEqual("2001:4860:4860::8888", "udp://[2001:4860:4860::8888]:53")
	assertDestEqual("[2001:4860:4860::8888]:53", "udp://[2001:4860:4860::8888]:53")
	assertDestEqual("udp://2001:4860:4860::8888", "udp://[2001:4860:4860::8888]:53")
	assertDestEqual("udp://[2001:4860:4860::8888]:53", "udp://[2001:4860:4860::8888]:53")
	assertDestEqual("tcp://2001:4860:4860::8888", "tcp://[2001:4860:4860::8888]:53")
	assertDestEqual("tcp://[2001:4860:4860::8888]:53", "tcp://[2001:4860:4860::8888]:53")
	assertDestEqual("udp://[2001:4860:4860::8888]:5300", "udp://[2001:4860:4860::8888]:5300")

}

func TestSSHFPAlgorithm(t *testing.T) {
	assert := assert.New(t)
	assert.Equal(uint8(1), sshfpAlgorithm(ssh.KeyAlgoRSA))
	assert.Equal(uint8(2), sshfpAlgorithm(ssh.KeyAlgoDSA))
	assert.Equal(uint8(3), sshfpAlgorithm(ssh.KeyAlgoECDSA256))
	assert.Equal(uint8(3), sshfpAlgorithm(ssh.KeyAlgoECDSA521))
	assert.Equal(uint8(4), sshfpAlgorithm(ssh.KeyAlgoED25519))
	assert.Equal(uint8(0), sshfpAlgorithm("ssh-unknown"))
}

func TestMatchSSHFP(t *testing.T) {
	assert := assert.New(t)

	pub, _, err := ed25519.GenerateKey(nil)
	assert.Nil(err)
	sshPub, err := ssh.NewPublicKey(pub)
	assert.Nil(err)

	blob := sshPub.Marshal()
	sha1Sum := sha1.Sum(blob)
	sha256Sum := sha256.Sum256(blob)

	// SHA-256 match.
	assert.True(matchSSHFP([]sshfpRecord{{algorithm: 4, fpType: sshfpTypeSHA256, fingerprint: sha256Sum[:]}}, sshPub))
	// SHA-1 match.
	assert.True(matchSSHFP([]sshfpRecord{{algorithm: 4, fpType: sshfpTypeSHA1, fingerprint: sha1Sum[:]}}, sshPub))
	// Match among multiple records.
	assert.True(matchSSHFP([]sshfpRecord{
		{algorithm: 1, fpType: sshfpTypeSHA256, fingerprint: sha256Sum[:]},
		{algorithm: 4, fpType: sshfpTypeSHA256, fingerprint: sha256Sum[:]},
	}, sshPub))

	// Wrong fingerprint -> no match.
	wrong := make([]byte, len(sha256Sum))
	assert.False(matchSSHFP([]sshfpRecord{{algorithm: 4, fpType: sshfpTypeSHA256, fingerprint: wrong}}, sshPub))
	// Wrong algorithm -> no match.
	assert.False(matchSSHFP([]sshfpRecord{{algorithm: 1, fpType: sshfpTypeSHA256, fingerprint: sha256Sum[:]}}, sshPub))
	// No records -> no match.
	assert.False(matchSSHFP(nil, sshPub))
}

func TestParseSSHFP(t *testing.T) {
	assert := assert.New(t)

	want := dnsmessage.MustNewName("example.com.")
	other := dnsmessage.MustNewName("evil.example.com.")
	fp := []byte{0xaa, 0xbb, 0xcc}
	answers := []dnsmessage.Resource{
		{
			Header: dnsmessage.ResourceHeader{Name: want, Type: dnsTypeSSHFP},
			Body:   &dnsmessage.UnknownResource{Type: dnsTypeSSHFP, Data: append([]byte{4, 2}, fp...)},
		},
		{
			// Non-SSHFP record is ignored.
			Header: dnsmessage.ResourceHeader{Name: want, Type: dnsmessage.TypeA},
			Body:   &dnsmessage.AResource{A: [4]byte{1, 2, 3, 4}},
		},
		{
			// Too short to be a valid SSHFP record.
			Header: dnsmessage.ResourceHeader{Name: want, Type: dnsTypeSSHFP},
			Body:   &dnsmessage.UnknownResource{Type: dnsTypeSSHFP, Data: []byte{4}},
		},
		{
			// Record for a different owner name is ignored.
			Header: dnsmessage.ResourceHeader{Name: other, Type: dnsTypeSSHFP},
			Body:   &dnsmessage.UnknownResource{Type: dnsTypeSSHFP, Data: append([]byte{4, 2}, fp...)},
		},
	}

	records := parseSSHFP(answers, want)
	assert.Len(records, 1)
	assert.Equal(uint8(4), records[0].algorithm)
	assert.Equal(uint8(2), records[0].fpType)
	assert.Equal(fp, records[0].fingerprint)
}

func TestParseSystemDNSServers(t *testing.T) {
	assert := assert.New(t)

	resolvConfServers := parseResolvConfDnsServers(`
# comment
nameserver 127.0.0.53
nameserver 8.8.8.8 # comment
nameserver 127.0.0.53
nameserver 2001:4860:4860::8888
`)
	assert.Equal([]dnsServer{
		{network: "udp", addr: "127.0.0.53:53"},
		{network: "udp", addr: "8.8.8.8:53"},
		{network: "udp", addr: "[2001:4860:4860::8888]:53"},
	}, resolvConfServers)

	scutilServers := parseScutilDnsServers(`
resolver #1
  nameserver[0] : 127.0.0.1
  nameserver[1] : 2606:4700:4700::1111
`)
	assert.Equal([]dnsServer{
		{network: "udp", addr: "127.0.0.1:53"},
		{network: "udp", addr: "[2606:4700:4700::1111]:53"},
	}, scutilServers)

	powerShellServers := parseDnsServerAddresses(`
192.168.1.1
2606:4700:4700::1111
fe80::1%12
`)
	assert.Equal([]dnsServer{
		{network: "udp", addr: "192.168.1.1:53"},
		{network: "udp", addr: "[2606:4700:4700::1111]:53"},
		{network: "udp", addr: "[fe80::1%12]:53"},
	}, powerShellServers)

	ipconfigServers := parseWindowsIpconfigDnsServers(`
   DNS Servers . . . . . . . . . . . : 192.168.1.1
                                       2606:4700:4700::1111
                                       fe80::1%12
   NetBIOS over Tcpip. . . . . . . . : Enabled
   DNS Servers . . . . . . . . . . . : 8.8.8.8
`)
	assert.Equal([]dnsServer{
		{network: "udp", addr: "192.168.1.1:53"},
		{network: "udp", addr: "[2606:4700:4700::1111]:53"},
		{network: "udp", addr: "[fe80::1%12]:53"},
		{network: "udp", addr: "8.8.8.8:53"},
	}, ipconfigServers)
}

func TestQuerySSHFPTCPHonorsNetwork(t *testing.T) {
	assert := assert.New(t)

	request, id, name := testSSHFPQuery(t)
	response := testSSHFPResponse(t, id, name, dnsOpCodeQuery, true)
	done := mockDNSDialer(t, "tcp", response)

	records, authenticated, err := querySSHFP(dnsServer{
		network: "tcp",
		addr:    "dns.test:53",
	}, request, id, name)
	assert.Nil(err)
	assert.False(authenticated)
	assert.Len(records, 1)
	assert.Equal(uint8(4), records[0].algorithm)
	assert.Nil(waitDNSServer(t, done))
}

func TestQuerySSHFPRejectsNonQueryOpcode(t *testing.T) {
	assert := assert.New(t)

	request, id, name := testSSHFPQuery(t)
	response := testSSHFPResponse(t, id, name, dnsmessage.OpCode(1), true)
	done := mockDNSDialer(t, "udp", response)

	_, _, err := querySSHFP(dnsServer{
		network: "udp",
		addr:    "dns.test:53",
	}, request, id, name)
	assert.NotNil(err)
	assert.Contains(err.Error(), "unexpected dns response")
	assert.Nil(waitDNSServer(t, done))
}

func TestQuerySSHFPDoesNotAuthenticateADBit(t *testing.T) {
	assert := assert.New(t)

	request, id, name := testSSHFPQuery(t)
	response := testSSHFPResponse(t, id, name, dnsOpCodeQuery, true)
	done := mockDNSDialer(t, "udp", response)

	records, authenticated, err := querySSHFP(dnsServer{
		network: "udp",
		addr:    "dns.test:53",
	}, request, id, name)
	assert.Nil(err)
	assert.False(authenticated)
	assert.Len(records, 1)
	assert.Nil(waitDNSServer(t, done))
}

func TestVerifyHostKeyDNSValidatedChainAccepts(t *testing.T) {
	assert := assert.New(t)

	sshPub, _, err := ed25519.GenerateKey(nil)
	assert.Nil(err)
	sshKey, err := ssh.NewPublicKey(sshPub)
	assert.Nil(err)

	responses, rootAnchor := testDNSSECChain(t, "host.example.test.", sshKey, false)
	withDNSSECTestLookup(t, responses, rootAnchor)

	matched, authenticated := verifyHostKeyDNS("host.example.test:22", sshKey)
	assert.True(matched)
	assert.True(authenticated)
}

func TestLookupSSHFPADBitOnlyDoesNotAuthenticate(t *testing.T) {
	assert := assert.New(t)

	sshPub, _, err := ed25519.GenerateKey(nil)
	assert.Nil(err)
	sshKey, err := ssh.NewPublicKey(sshPub)
	assert.Nil(err)
	response := testSSHFPOnlyResponse(t, "host.example.test.", sshKey, true)
	withDNSSECTestLookup(t, map[string]*dnsmessage.Message{
		testLookupKey("host.example.test.", dnsTypeSSHFP): response,
	}, nil)

	matched, authenticated := verifyHostKeyDNS("host.example.test", sshKey)
	assert.True(matched)
	assert.False(authenticated)
}

func TestLookupSSHFPRejectsTamperedRRSIG(t *testing.T) {
	assert := assert.New(t)

	sshPub, _, err := ed25519.GenerateKey(nil)
	assert.Nil(err)
	sshKey, err := ssh.NewPublicKey(sshPub)
	assert.Nil(err)

	responses, rootAnchor := testDNSSECChain(t, "host.example.test.", sshKey, true)
	withDNSSECTestLookup(t, responses, rootAnchor)

	matched, authenticated := verifyHostKeyDNS("host.example.test", sshKey)
	assert.True(matched)
	assert.False(authenticated)
}

func TestDnsName(t *testing.T) {
	assert := assert.New(t)
	assert.Equal("example.com.", dnsName("example.com"))
	assert.Equal("example.com.", dnsName("example.com."))
	assert.Equal("example.com.", dnsName("[example.com]"))
}

func testSSHFPQuery(t *testing.T) ([]byte, uint16, dnsmessage.Name) {
	t.Helper()
	id := uint16(0x1234)
	name := dnsmessage.MustNewName("example.com.")
	optHeader := dnsmessage.ResourceHeader{}
	if err := optHeader.SetEDNS0(dnsEDNSPayload, dnsmessage.RCodeSuccess, true); err != nil {
		t.Fatal(err)
	}
	query := dnsmessage.Message{
		Header: dnsmessage.Header{ID: id, RecursionDesired: true, CheckingDisabled: true},
		Questions: []dnsmessage.Question{{
			Name:  name,
			Type:  dnsTypeSSHFP,
			Class: dnsmessage.ClassINET,
		}},
		Additionals: []dnsmessage.Resource{{
			Header: optHeader,
			Body:   &dnsmessage.OPTResource{},
		}},
	}
	request, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return request, id, name
}

func testSSHFPResponse(t *testing.T, id uint16, name dnsmessage.Name, opCode dnsmessage.OpCode, authenticated bool) []byte {
	t.Helper()
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:            id,
			Response:      true,
			OpCode:        opCode,
			AuthenticData: authenticated,
			RCode:         dnsmessage.RCodeSuccess,
		},
		Questions: []dnsmessage.Question{{
			Name:  name,
			Type:  dnsTypeSSHFP,
			Class: dnsmessage.ClassINET,
		}},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: name, Type: dnsTypeSSHFP, Class: dnsmessage.ClassINET},
			Body:   &dnsmessage.UnknownResource{Type: dnsTypeSSHFP, Data: []byte{4, 2, 0xaa, 0xbb}},
		}},
	}
	response, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func testDNSSECChain(t *testing.T, host string, key ssh.PublicKey, tamper bool) (map[string]*dnsmessage.Message, []dsRecord) {
	t.Helper()

	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	assert.Nil(t, err)
	tldPub, tldPriv, err := ed25519.GenerateKey(nil)
	assert.Nil(t, err)
	zonePub, zonePriv, err := ed25519.GenerateKey(nil)
	assert.Nil(t, err)

	rootKey := testDNSKEYRecord(".", rootPub)
	tldKey := testDNSKEYRecord("test.", tldPub)
	zoneKey := testDNSKEYRecord("example.test.", zonePub)
	tldDS := testDSRecord(t, "test.", tldKey)
	zoneDS := testDSRecord(t, "example.test.", zoneKey)
	sshfp := testSSHFPRecord(host, key)

	rootDigest, ok := dnskeyDigest(".", rootKey, dnssecDigestSHA256)
	assert.True(t, ok)
	rootAnchor := []dsRecord{{
		dnssecRecord: dnssecRecord{name: ".", rrType: dnsTypeDS, class: dnsmessage.ClassINET, ttl: 3600},
		keyTag:       rootKey.keyTag,
		algorithm:    rootKey.algorithm,
		digestType:   dnssecDigestSHA256,
		digest:       rootDigest,
	}}

	sshfpResponse := testSignedResponse(t, host, dnsTypeSSHFP, []dnssecRecord{sshfp}, "example.test.", zoneKey, zonePriv)
	if tamper {
		testTamperRRSIG(t, sshfpResponse)
	}

	return map[string]*dnsmessage.Message{
		testLookupKey(host, dnsTypeSSHFP):             sshfpResponse,
		testLookupKey("example.test.", dnsTypeDNSKEY): testSignedResponse(t, "example.test.", dnsTypeDNSKEY, []dnssecRecord{zoneKey.dnssecRecord}, "example.test.", zoneKey, zonePriv),
		testLookupKey("example.test.", dnsTypeDS):     testSignedResponse(t, "example.test.", dnsTypeDS, []dnssecRecord{zoneDS.dnssecRecord}, "test.", tldKey, tldPriv),
		testLookupKey("test.", dnsTypeDNSKEY):         testSignedResponse(t, "test.", dnsTypeDNSKEY, []dnssecRecord{tldKey.dnssecRecord}, "test.", tldKey, tldPriv),
		testLookupKey("test.", dnsTypeDS):             testSignedResponse(t, "test.", dnsTypeDS, []dnssecRecord{tldDS.dnssecRecord}, ".", rootKey, rootPriv),
		testLookupKey(".", dnsTypeDNSKEY):             testSignedResponse(t, ".", dnsTypeDNSKEY, []dnssecRecord{rootKey.dnssecRecord}, ".", rootKey, rootPriv),
	}, rootAnchor
}

func testSSHFPOnlyResponse(t *testing.T, host string, key ssh.PublicKey, authenticated bool) *dnsmessage.Message {
	t.Helper()
	name := dnsmessage.MustNewName(canonicalDNSName(host))
	return &dnsmessage.Message{
		Header: dnsmessage.Header{Response: true, RecursionAvailable: true, AuthenticData: authenticated, RCode: dnsmessage.RCodeSuccess},
		Questions: []dnsmessage.Question{{
			Name:  name,
			Type:  dnsTypeSSHFP,
			Class: dnsmessage.ClassINET,
		}},
		Answers: []dnsmessage.Resource{testResource(testSSHFPRecord(host, key))},
	}
}

func withDNSSECTestLookup(t *testing.T, responses map[string]*dnsmessage.Message, anchors []dsRecord) {
	t.Helper()
	oldLookup := lookupDNSSEC
	oldAnchors := dnssecRootTrustAnchors
	oldNow := dnssecNow
	now := time.Now()
	lookupDNSSEC = func(name string, rrType dnsmessage.Type) (*dnsmessage.Message, error) {
		response := responses[testLookupKey(name, rrType)]
		if response == nil {
			return nil, fmt.Errorf("missing test DNS response for %s %d", name, rrType)
		}
		return response, nil
	}
	if anchors != nil {
		dnssecRootTrustAnchors = anchors
	}
	dnssecNow = func() time.Time { return now }
	t.Cleanup(func() {
		lookupDNSSEC = oldLookup
		dnssecRootTrustAnchors = oldAnchors
		dnssecNow = oldNow
	})
}

func testLookupKey(name string, rrType dnsmessage.Type) string {
	return fmt.Sprintf("%s/%d", canonicalDNSName(name), rrType)
}

func testDNSKEYRecord(name string, publicKey ed25519.PublicKey) dnskeyRecord {
	rdata := make([]byte, 4+len(publicKey))
	binary.BigEndian.PutUint16(rdata[0:2], 257)
	rdata[2] = 3
	rdata[3] = dnssecAlgorithmED25519
	copy(rdata[4:], publicKey)
	record := dnssecRecord{
		name:   canonicalDNSName(name),
		rrType: dnsTypeDNSKEY,
		class:  dnsmessage.ClassINET,
		ttl:    3600,
		rdata:  rdata,
	}
	return dnskeyRecord{
		dnssecRecord: record,
		flags:        257,
		protocol:     3,
		algorithm:    dnssecAlgorithmED25519,
		publicKey:    append([]byte(nil), publicKey...),
		keyTag:       dnskeyTag(rdata),
	}
}

func testDSRecord(t *testing.T, name string, key dnskeyRecord) dsRecord {
	t.Helper()
	digest, ok := dnskeyDigest(name, key, dnssecDigestSHA256)
	assert.True(t, ok)
	rdata := appendUint16(nil, key.keyTag)
	rdata = append(rdata, key.algorithm, dnssecDigestSHA256)
	rdata = append(rdata, digest...)
	return dsRecord{
		dnssecRecord: dnssecRecord{
			name:   canonicalDNSName(name),
			rrType: dnsTypeDS,
			class:  dnsmessage.ClassINET,
			ttl:    3600,
			rdata:  rdata,
		},
		keyTag:     key.keyTag,
		algorithm:  key.algorithm,
		digestType: dnssecDigestSHA256,
		digest:     digest,
	}
}

func testSSHFPRecord(name string, key ssh.PublicKey) dnssecRecord {
	sum := sha256.Sum256(key.Marshal())
	rdata := append([]byte{sshfpAlgorithm(key.Type()), sshfpTypeSHA256}, sum[:]...)
	return dnssecRecord{
		name:   canonicalDNSName(name),
		rrType: dnsTypeSSHFP,
		class:  dnsmessage.ClassINET,
		ttl:    3600,
		rdata:  rdata,
	}
}

func testSignedResponse(t *testing.T, owner string, rrType dnsmessage.Type, records []dnssecRecord, signer string, signerKey dnskeyRecord, signerPriv ed25519.PrivateKey) *dnsmessage.Message {
	t.Helper()
	owner = canonicalDNSName(owner)
	now := uint32(time.Now().Unix())
	sig := rrsigRecord{
		dnssecRecord: dnssecRecord{
			name:   owner,
			rrType: dnsTypeRRSIG,
			class:  dnsmessage.ClassINET,
			ttl:    3600,
		},
		typeCovered: rrType,
		algorithm:   signerKey.algorithm,
		labels:      uint8(dnsLabelCount(owner)),
		originalTTL: 3600,
		expiration:  now + 3600,
		inception:   now - 3600,
		keyTag:      signerKey.keyTag,
		signerName:  canonicalDNSName(signer),
	}
	signedData, err := rrsetSignedData(records, sig)
	assert.Nil(t, err)
	sig.signature = ed25519.Sign(signerPriv, signedData)
	sig.rdata = testRRSIGRData(t, sig)

	answers := make([]dnsmessage.Resource, 0, len(records)+1)
	for _, record := range records {
		answers = append(answers, testResource(record))
	}
	answers = append(answers, testResource(sig.dnssecRecord))

	name := dnsmessage.MustNewName(owner)
	return &dnsmessage.Message{
		Header: dnsmessage.Header{Response: true, RecursionAvailable: true, RCode: dnsmessage.RCodeSuccess},
		Questions: []dnsmessage.Question{{
			Name:  name,
			Type:  rrType,
			Class: dnsmessage.ClassINET,
		}},
		Answers: answers,
	}
}

func testRRSIGRData(t *testing.T, sig rrsigRecord) []byte {
	t.Helper()
	rdata := appendUint16(nil, uint16(sig.typeCovered))
	rdata = append(rdata, sig.algorithm, sig.labels)
	rdata = appendUint32(rdata, sig.originalTTL)
	rdata = appendUint32(rdata, sig.expiration)
	rdata = appendUint32(rdata, sig.inception)
	rdata = appendUint16(rdata, sig.keyTag)
	signer, err := packDNSName(sig.signerName)
	assert.Nil(t, err)
	rdata = append(rdata, signer...)
	return append(rdata, sig.signature...)
}

func testResource(record dnssecRecord) dnsmessage.Resource {
	name := dnsmessage.MustNewName(canonicalDNSName(record.name))
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: name, Type: record.rrType, Class: record.class, TTL: record.ttl},
		Body:   &dnsmessage.UnknownResource{Type: record.rrType, Data: append([]byte(nil), record.rdata...)},
	}
}

func testTamperRRSIG(t *testing.T, response *dnsmessage.Message) {
	t.Helper()
	for i := range response.Answers {
		if response.Answers[i].Header.Type != dnsTypeRRSIG {
			continue
		}
		unknown, ok := response.Answers[i].Body.(*dnsmessage.UnknownResource)
		assert.True(t, ok)
		assert.NotEmpty(t, unknown.Data)
		unknown.Data[len(unknown.Data)-1] ^= 0xff
		return
	}
	t.Fatal("missing RRSIG to tamper")
}

func mockDNSDialer(t *testing.T, expectedNetwork string, response []byte) <-chan error {
	t.Helper()
	oldDialDNS := dialDNS
	done := make(chan error, 1)
	dialDNS = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		if network != expectedNetwork {
			return nil, fmt.Errorf("expected %s DNS network, got %s", expectedNetwork, network)
		}
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			if expectedNetwork == "tcp" {
				done <- servePipeTCPDNS(server, response)
				return
			}
			done <- servePipeUDPDNS(server, response)
		}()
		return client, nil
	}
	t.Cleanup(func() { dialDNS = oldDialDNS })
	return done
}

func servePipeUDPDNS(conn net.Conn, response []byte) error {
	buf := make([]byte, 512)
	if _, err := conn.Read(buf); err != nil {
		return err
	}
	_, err := conn.Write(response)
	return err
}

func servePipeTCPDNS(conn net.Conn, response []byte) error {
	var length [2]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return err
	}
	request := make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err := io.ReadFull(conn, request); err != nil {
		return err
	}
	reply := make([]byte, len(response)+2)
	binary.BigEndian.PutUint16(reply[:2], uint16(len(response)))
	copy(reply[2:], response)
	_, err := conn.Write(reply)
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

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
	"fmt"
	"testing"

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
			Header: dnsmessage.ResourceHeader{Name: want, Type: dnsmessage.Type(44)},
			Body:   &dnsmessage.UnknownResource{Type: dnsmessage.Type(44), Data: append([]byte{4, 2}, fp...)},
		},
		{
			// Non-SSHFP record is ignored.
			Header: dnsmessage.ResourceHeader{Name: want, Type: dnsmessage.TypeA},
			Body:   &dnsmessage.AResource{A: [4]byte{1, 2, 3, 4}},
		},
		{
			// Too short to be a valid SSHFP record.
			Header: dnsmessage.ResourceHeader{Name: want, Type: dnsmessage.Type(44)},
			Body:   &dnsmessage.UnknownResource{Type: dnsmessage.Type(44), Data: []byte{4}},
		},
		{
			// Record for a different owner name is ignored.
			Header: dnsmessage.ResourceHeader{Name: other, Type: dnsmessage.Type(44)},
			Body:   &dnsmessage.UnknownResource{Type: dnsmessage.Type(44), Data: append([]byte{4, 2}, fp...)},
		},
	}

	records := parseSSHFP(answers, want)
	assert.Len(records, 1)
	assert.Equal(uint8(4), records[0].algorithm)
	assert.Equal(uint8(2), records[0].fpType)
	assert.Equal(fp, records[0].fingerprint)
}

func TestDnsName(t *testing.T) {
	assert := assert.New(t)
	assert.Equal("example.com.", dnsName("example.com"))
	assert.Equal("example.com.", dnsName("example.com."))
	assert.Equal("example.com.", dnsName("[example.com]"))
}

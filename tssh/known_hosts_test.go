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
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/skeema/knownhosts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	xkh "golang.org/x/crypto/ssh/knownhosts"
)

func newKnownHostsTestKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := ssh.NewPublicKey(public)
	require.NoError(t, err)
	return key
}

func writeKnownHostsTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	return path
}

func checkKnownHostsTestKey(db *knownhosts.HostKeyDB, host string, port int, key ssh.PublicKey) error {
	return db.HostKeyCallback()(net.JoinHostPort(host, strconv.Itoa(port)),
		&net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: port}, key)
}

func TestNewKnownHostsDBIgnoresMalformedEntries(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("TMPDIR", tempDir)
	key := newKnownHostsTestKey(t)
	validLine := knownhosts.Line([]string{"valid.example"}, key)
	malformedLine := "broken.example ssh-rsa not-base64 ssh-rsa " + strings.Repeat("A", 372)
	content := "# retained comment\n" + malformedLine + "\n" + validLine + "\n"
	path := writeKnownHostsTestFile(t, tempDir, "known_hosts", content)

	db, malformed, err := newKnownHostsDB(path)
	require.NoError(t, err)
	require.Len(t, malformed, 1)
	assert.Equal(t, path, malformed[0].path)
	assert.Equal(t, 2, malformed[0].line)
	assert.Contains(t, malformed[0].reason, "illegal base64")
	assert.NotContains(t, malformed[0].reason, strings.Repeat("A", 32))
	assert.NoError(t, checkKnownHostsTestKey(db, "valid.example", 22, key))

	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, content, string(after))
	entries, err := os.ReadDir(tempDir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "known_hosts", entries[0].Name())
}

func TestNewKnownHostsDBIgnoresMultipleMalformedEntries(t *testing.T) {
	tempDir := t.TempDir()
	key := newKnownHostsTestKey(t)
	first := writeKnownHostsTestFile(t, tempDir, "known_hosts", "first ssh-ed25519 !!!\n")
	second := writeKnownHostsTestFile(t, tempDir, "known_hosts2",
		"second ssh-rsa !!!\n"+knownhosts.Line([]string{"valid.example"}, key)+"\n")

	db, malformed, err := newKnownHostsDB(first, second)
	require.NoError(t, err)
	require.Len(t, malformed, 2)
	assert.Equal(t, first, malformed[0].path)
	assert.Equal(t, second, malformed[1].path)
	assert.NoError(t, checkKnownHostsTestKey(db, "valid.example", 22, key))
}

func TestNewKnownHostsDBPreservesEnhancedMatching(t *testing.T) {
	tempDir := t.TempDir()
	key := newKnownHostsTestKey(t)
	revokedKey := newKnownHostsTestKey(t)
	hashedHost := "hashed.example"
	content := strings.Join([]string{
		"broken ssh-ed25519 !!!",
		knownhosts.Line([]string{"*.example.com"}, key),
		knownhosts.Line([]string{xkh.HashHostname(hashedHost)}, key),
		"@cert-authority " + knownhosts.Line([]string{"cert.example"}, key),
		"@revoked " + knownhosts.Line([]string{"revoked.example"}, revokedKey),
	}, "\n") + "\n"
	path := writeKnownHostsTestFile(t, tempDir, "known_hosts", content)

	db, malformed, err := newKnownHostsDB(path)
	require.NoError(t, err)
	require.Len(t, malformed, 1)
	assert.NoError(t, db.HostKeyCallback()("wild.example.com:2222",
		&net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 2222}, key))
	assert.NoError(t, checkKnownHostsTestKey(db, hashedHost, 22, key))
	assert.Contains(t, db.HostKeyAlgorithms("cert.example:22"), ssh.CertAlgoED25519v01)

	err = checkKnownHostsTestKey(db, "revoked.example", 22, revokedKey)
	var revokedErr *xkh.RevokedError
	assert.True(t, errors.As(err, &revokedErr))
}

func TestNewKnownHostsDBWithOnlyMalformedEntries(t *testing.T) {
	path := writeKnownHostsTestFile(t, t.TempDir(), "known_hosts", "broken ssh-ed25519 !!!\n")
	db, malformed, err := newKnownHostsDB(path)
	require.NoError(t, err)
	require.Len(t, malformed, 1)

	err = checkKnownHostsTestKey(db, "unknown.example", 22, newKnownHostsTestKey(t))
	assert.True(t, knownhosts.IsHostUnknown(err))
}

func TestNewKnownHostsDBKeepsNonParseErrorsFatal(t *testing.T) {
	_, malformed, err := newKnownHostsDB(t.TempDir())
	require.Error(t, err)
	assert.Nil(t, malformed)
}

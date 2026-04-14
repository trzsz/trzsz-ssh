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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecSecretCommand(t *testing.T) {
	assert := assert.New(t)

	assert.Equal("hello", execSecretCommand("echo hello", "myhost"))

	assert.Equal("secret", execSecretCommand("echo '  secret  '", "myhost"))

	assert.Equal("myhost", execSecretCommand("echo %n", "myhost"))

	assert.Equal("%", execSecretCommand("echo %%", "myhost"))

	assert.Equal("", execSecretCommand("false", "myhost"))

	assert.Equal("", execSecretCommand("/nonexistent/command", "myhost"))

	assert.Equal("", execSecretCommand("echo -n ''", "myhost"))

	result := execSecretCommand("printf 'line1\\nline2'", "myhost")
	assert.Equal("line1\nline2", result)
}

func TestExecSecretCommandTokens(t *testing.T) {
	assert := assert.New(t)

	// without userConfig, %h falls back to alias, %p to "22", %r to ""
	assert.Equal("myhost", execSecretCommand("echo %h", "myhost"))
	assert.Equal("22", execSecretCommand("echo %p", "myhost"))
	assert.Equal("", execSecretCommand("echo -n %r", "myhost"))
}

func TestGetSecretConfigWithCommand(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	tmpDir := t.TempDir()

	sshConfig := filepath.Join(tmpDir, "config")
	err := os.WriteFile(sshConfig, []byte(`
Host cmdhost
    HostName 10.0.0.1
    User testuser
    PasswordCommand echo my-secret-password

Host enchost
    HostName 10.0.0.2
    User testuser

Host plainhost
    HostName 10.0.0.3
    User testuser
    Password plain-text-pass

Host tokenhost
    HostName 10.0.0.4
    User testuser
    PasswordCommand echo password-for-%n
`), 0600)
	require.NoError(err)

	origConfig := userConfig
	defer func() { userConfig = origConfig }()
	userConfig = &tsshConfig{}
	userConfig.configPath = sshConfig
	userConfig.exConfigPath = filepath.Join(tmpDir, "password")

	// PasswordCommand should return the command output
	assert.Equal("my-secret-password", getSecretConfig("cmdhost", "Password"))

	// host without any password config should return empty
	assert.Equal("", getSecretConfig("enchost", "Password"))

	// plain Password should still work as fallback
	assert.Equal("plain-text-pass", getSecretConfig("plainhost", "Password"))

	// %n token in PasswordCommand should be expanded to the alias
	assert.Equal("password-for-tokenhost", getSecretConfig("tokenhost", "Password"))
}

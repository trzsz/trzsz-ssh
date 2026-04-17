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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trzsz/ssh_config"
)

func TestExecSecretCommand(t *testing.T) {
	assert := assert.New(t)
	oriEnableWarning, oriUserConfig := enableWarningLogging, userConfig
	enableWarningLogging, userConfig = false, &tsshConfig{}
	defer func() { enableWarningLogging, userConfig = oriEnableWarning, oriUserConfig }()

	param, err := getSshParam(&sshArgs{Destination: "myhost"}, false)
	require.NoError(t, err)

	assert.Equal("hello", execSecretCommand(param, "echo hello"))
	assert.Equal("secret", execSecretCommand(param, "echo '  secret  '"))
	assert.Equal("myhost", execSecretCommand(param, "echo %n"))
	assert.Equal("%", execSecretCommand(param, "echo %%"))
	assert.Equal("", execSecretCommand(param, "false"))
	assert.Equal("", execSecretCommand(param, "/nonexistent/command"))
	assert.Equal("", execSecretCommand(param, "echo -n ''"))

	result := execSecretCommand(param, "printf 'line1\\nline2'")
	assert.Equal("line1\nline2", result)
}

func TestExecSecretCommandTokens(t *testing.T) {
	assert := assert.New(t)
	oriEnableWarning, oriUserConfig := enableWarningLogging, userConfig
	enableWarningLogging, userConfig = false, &tsshConfig{}
	defer func() { enableWarningLogging, userConfig = oriEnableWarning, oriUserConfig }()

	param, err := getSshParam(&sshArgs{Destination: "myhost"}, false)
	require.NoError(t, err)

	assert.Equal("myhost", execSecretCommand(param, "echo %h"))
	assert.Equal("22", execSecretCommand(param, "echo %p"))
	assert.Equal(param.user, execSecretCommand(param, "echo %r"))
}

func TestGetSecretConfigWithCommand(t *testing.T) {
	assert := assert.New(t)
	oriEnableWarning, oriUserConfig := enableWarningLogging, userConfig
	enableWarningLogging, userConfig = false, &tsshConfig{}
	defer func() { enableWarningLogging, userConfig = oriEnableWarning, oriUserConfig }()

	var err error
	userConfig.exConfig, err = ssh_config.DecodeBytes([]byte(`
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
`))
	require.NoError(t, err)

	param := func(alias string) *sshParam {
		param, err := getSshParam(&sshArgs{Destination: alias}, false)
		require.NoError(t, err)
		return param
	}

	// PasswordCommand should return the command output
	assert.Equal("my-secret-password", getSecretConfig(param("cmdhost"), "Password"))

	// host without any password config should return empty
	assert.Equal("", getSecretConfig(param("enchost"), "Password"))

	// plain Password should still work as fallback
	assert.Equal("plain-text-pass", getSecretConfig(param("plainhost"), "Password"))

	// %n token in PasswordCommand should be expanded to the alias
	assert.Equal("password-for-tokenhost", getSecretConfig(param("tokenhost"), "Password"))
}

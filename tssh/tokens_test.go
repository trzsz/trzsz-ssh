/*
MIT License

Copyright (c) 2023-2024 The Trzsz SSH Authors.

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
)

func TestExpandTokens(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	originalGetHostname := getHostname
	defer func() {
		getHostname = originalGetHostname
	}()
	getHostname = func() string { return "myhostname.mydomain.com" }

	args := &sshArgs{
		Destination: "dest",
	}
	param := &sshParam{
		host:  "127.0.0.1",
		port:  "1337",
		user:  "penny",
		proxy: []string{"jump"},
	}
	assertProxyCommand := func(original, expanded, errMsg string) {
		t.Helper()
		result, err := expandTokens(original, args, param, "%hnpr")
		if errMsg != "" {
			require.NotNil(err)
			assert.Equal(original, result)
			assert.Equal(errMsg, err.Error())
			return
		}
		require.Nil(err)
		assert.Equal(expanded, result)
	}

	assertProxyCommand("%%", "%", "")
	assertProxyCommand("%h", "127.0.0.1", "")
	assertProxyCommand("%n", "dest", "")
	assertProxyCommand("%p", "1337", "")
	assertProxyCommand("%r", "penny", "")
	assertProxyCommand("a_%%_%r_%p_%n_%h_Z", "a_%_penny_1337_dest_127.0.0.1_Z", "")

	assertProxyCommand("%l", "%l", "token [%l] in [%l] is not supported")
	assertProxyCommand("a_%h_%C", "a_127.0.0.1_%C", "token [%C] in [a_%h_%C] is not supported")

	assertControlPath := func(original, expanded, errMsg string) {
		t.Helper()
		result, err := expandTokens(original, args, param, "%CdhikLlnpru")
		if errMsg != "" {
			require.NotNil(err)
			assert.Equal(errMsg, err.Error())
			return
		}
		require.Nil(err)
		assert.Equal(expanded, result)
	}

	assertControlPath("%p和%r", "1337和penny", "")
	assertControlPath("%%%h%n", "%127.0.0.1dest", "")
	assertControlPath("%L", "myhostname", "")
	assertControlPath("%l", "myhostname.mydomain.com", "")

	assertControlPath("/A/%C/B", "/A/07f25c03a322b120bcaa54d2dd0a618f2673cb1c/B", "")

	assertControlPath("%j", "%j", "token [%j] in [%j] is not supported")
	assertControlPath("p_%h_%d", "p_127.0.0.1_%d", "token [%d] in [p_%h_%d] is not supported yet")
	assertControlPath("h%", "h%", "[h%] ends with % is invalid")
}

func TestProxyJumpToken(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	originalGetHostname := getHostname
	defer func() {
		getHostname = originalGetHostname
	}()
	getHostname = func() string { return "myhostname.mydomain.com" }

	args := &sshArgs{
		Destination: "dest",
	}
	param := &sshParam{
		host: "127.0.0.1",
		port: "1337",
		user: "penny",
	}

	assertProxyJumpToken := func(original, expanded string) {
		t.Helper()
		result, err := expandTokens(original, args, param, "%CdhijkLlnpru")
		require.Nil(err)
		assert.Equal(expanded, result)
	}

	assertProxyJumpToken("%j", "")
	assertProxyJumpToken("_%j_", "__")
	assertProxyJumpToken("%C", "07f25c03a322b120bcaa54d2dd0a618f2673cb1c")

	param.proxy = []string{"jump"}
	assertProxyJumpToken("%j", "jump")
	assertProxyJumpToken("_%j_", "_jump_")
	assertProxyJumpToken("%C", "5fa1bcd29f7fd4f17b669ffb83deb4243d52b1fa")

	param.proxy = []string{"jump", "server"}
	assertProxyJumpToken("%j", "server")
	assertProxyJumpToken("_%j_", "_server_")
	assertProxyJumpToken("/%C/", "/dc78bc912643b984e78d7d80f9912dbc794d2455/")
}

func TestInvalidHost(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	assertInvalidHost := func(host string) {
		t.Helper()
		_, err := expandTokens("%h", &sshArgs{}, &sshParam{host: host}, "%hnpr")
		require.NotNil(err)
		assert.Equal("hostname contains invalid characters", err.Error())
	}

	assertInvalidHost("-invalidhostname")
	assertInvalidHost("invalid'hostname")
	assertInvalidHost("invalid`hostname")
	assertInvalidHost("invalid\"hostname")
	assertInvalidHost("invalid$hostname")
	assertInvalidHost("invalid\\hostname")
	assertInvalidHost("invalid;hostname")
	assertInvalidHost("invalid&hostname")
	assertInvalidHost("invalid<hostname")
	assertInvalidHost("invalid>hostname")
	assertInvalidHost("invalid|hostname")
	assertInvalidHost("invalid(hostname")
	assertInvalidHost("invalid)hostname")
	assertInvalidHost("invalid{hostname")
	assertInvalidHost("invalid}hostname")
	assertInvalidHost("invalid hostname")
	assertInvalidHost("invalid\thostname")
	assertInvalidHost("invalid\rhostname")
	assertInvalidHost("invalid\nhostname")
	assertInvalidHost("invalid\vhostname")
	assertInvalidHost("invalid\fhostname")
	assertInvalidHost("invalid\u0007hostname")
	assertInvalidHost("invalid\u0018hostname")
	assertInvalidHost("invalid\u007fhostname")
	assertInvalidHost("invalid\u2028hostname")
	assertInvalidHost("invalid\u2029hostname")
}

func TestInvalidUser(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	assertInvalidUser := func(user string) {
		t.Helper()
		_, err := expandTokens("%r", &sshArgs{}, &sshParam{user: user}, "%hnpr")
		require.NotNil(err)
		assert.Equal("remote username contains invalid characters", err.Error())
	}

	assertInvalidUser("-invalidusername")
	assertInvalidUser("invalid'username")
	assertInvalidUser("invalid`username")
	assertInvalidUser("invalid\"username")
	assertInvalidUser("invalid;username")
	assertInvalidUser("invalid&username")
	assertInvalidUser("invalid<username")
	assertInvalidUser("invalid>username")
	assertInvalidUser("invalid|username")
	assertInvalidUser("invalid(username")
	assertInvalidUser("invalid)username")
	assertInvalidUser("invalid{username")
	assertInvalidUser("invalid}username")
	assertInvalidUser("invalid -username")
	assertInvalidUser("invalid\t-username")
	assertInvalidUser("invalid\r-username")
	assertInvalidUser("invalid\n-username")
	assertInvalidUser("invalidusername\\")
}

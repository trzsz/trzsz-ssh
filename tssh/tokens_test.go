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
)

func TestExpandTokens(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	originalGetHostname := getHostname
	_, _, _, _ = getOpenSSH()
	originalOpenSshMajor, originalOpenSshMinor, originalOpenSshErr := openSshMajor, openSshMinor, openSshErr
	defer func() {
		getHostname = originalGetHostname
		openSshMajor, openSshMinor, openSshErr = originalOpenSshMajor, originalOpenSshMinor, originalOpenSshErr
	}()
	getHostname = func() string { return "myhostname.mydomain.com" }
	openSshMajor, openSshMinor, openSshErr = 9, 5, nil

	param := &sshParam{
		args: &sshArgs{
			Destination: "dest",
		},
		host:    "127.0.0.1",
		port:    "1337",
		user:    "penny",
		proxies: []string{"jump"},
	}
	assertProxyCommand := func(original, expanded, errMsg string) {
		t.Helper()
		result, err := expandTokens(original, param, "%hnpr")
		if errMsg != "" {
			require.NotNil(err)
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

	assertProxyCommand("%l", "", "token [%l] in [%l] is not supported")
	assertProxyCommand("a_%h_%C", "", "token [%C] in [a_%h_%C] is not supported")

	assertControlPath := func(original, expanded, errMsg string) {
		t.Helper()
		result, err := expandTokens(original, param, "%CdhikLlnpru")
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

	assertControlPath("%j", "", "token [%j] in [%j] is not supported")
	assertControlPath("p_%h_%d", "", "token [%d] in [p_%h_%d] is not supported yet")
	assertControlPath("h%", "", "[h%] ends with % is invalid")
}

func TestProxyJumpToken(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	originalGetHostname := getHostname
	_, _, _, _ = getOpenSSH()
	originalOpenSshMajor, originalOpenSshMinor, originalOpenSshErr := openSshMajor, openSshMinor, openSshErr
	defer func() {
		getHostname = originalGetHostname
		openSshMajor, openSshMinor, openSshErr = originalOpenSshMajor, originalOpenSshMinor, originalOpenSshErr
	}()
	getHostname = func() string { return "myhostname.mydomain.com" }
	openSshMajor, openSshMinor, openSshErr = 9, 6, nil

	param := &sshParam{
		args: &sshArgs{
			Destination: "dest",
		},
		host: "127.0.0.1",
		port: "1337",
		user: "penny",
	}

	assertProxyJumpToken := func(original, expanded string) {
		t.Helper()
		result, err := expandTokens(original, param, "%CdhijkLlnpru")
		require.Nil(err)
		assert.Equal(expanded, result)
	}

	assertProxyJumpToken("%j", "")
	assertProxyJumpToken("_%j_", "__")
	assertProxyJumpToken("%C", "07f25c03a322b120bcaa54d2dd0a618f2673cb1c")

	param.proxies = []string{"jump"}
	assertProxyJumpToken("%j", "jump")
	assertProxyJumpToken("_%j_", "_jump_")
	assertProxyJumpToken("%C", "5fa1bcd29f7fd4f17b669ffb83deb4243d52b1fa")

	param.proxies = []string{"jump", "server"}
	assertProxyJumpToken("%j", "server")
	assertProxyJumpToken("_%j_", "_server_")
	assertProxyJumpToken("/%C/", "/dc78bc912643b984e78d7d80f9912dbc794d2455/")

	// %j should return only the host, stripping the user and port if present.
	param.proxies = []string{"user@jump"}
	assertProxyJumpToken("%j", "jump")

	param.proxies = []string{"jump:2222"}
	assertProxyJumpToken("%j", "jump")

	param.proxies = []string{"user@jump:2222"}
	assertProxyJumpToken("%j", "jump")

	param.proxies = []string{"[::1]"}
	assertProxyJumpToken("%j", "::1")

	param.proxies = []string{"user@[::1]:2222"}
	assertProxyJumpToken("%j", "::1")

	// For multiple hops, %j should return the host of the last hop.
	param.proxies = []string{"jump1", "user@jump2:2222"}
	assertProxyJumpToken("%j", "jump2")
}

func TestInvalidHost(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	assertInvalidHost := func(host string) {
		t.Helper()
		_, err := expandTokens("%h", &sshParam{args: &sshArgs{}, host: host}, "%hnpr")
		require.NotNil(err)
		assert.Contains(err.Error(), "contains invalid characters")
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

// %C is the OpenSSH connection hash (ssh_connection_hash in readconf.c):
// sha1(thishost + remhost + portstr + remuser [+ jumphost]), where jumphost
// is the host of the last proxy jump. parse_jump() works backwards through
// the jump list, strips the user and port, and keeps only the last hop.
// OpenSSH 9.6 and later include the jump host in the hash; older versions
// do not. The %j token was introduced in OpenSSH 9.6.
//
// Verified the hash calculation against OpenSSH 9.9p2 on macOS using:
//
//	/usr/bin/ssh -F /dev/null -G -o ControlPath=cm-%C -J jump -l myuser -p 22 myhost
//
// The resulting hash matches:
//
//	sha1(thishost + "myhost" + "22" + "myuser" + "jump")
//
// The same hash is produced by -J user@jump, -J jump:2222, and
// -J user@jump:2222. For multiple hops, only the last hop is included,
// so -J a,b produces the same hash as -J b.
//
// The expected hashes below are computed using the stubbed local hostname "mylocal".
func TestControlPathHash(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	originalGetHostname := getHostname
	_, _, _, _ = getOpenSSH()
	originalOpenSshMajor, originalOpenSshMinor, originalOpenSshErr := openSshMajor, openSshMinor, openSshErr
	defer func() {
		getHostname = originalGetHostname
		openSshMajor, openSshMinor, openSshErr = originalOpenSshMajor, originalOpenSshMinor, originalOpenSshErr
	}()
	getHostname = func() string { return "mylocal" }

	newParam := func(proxies ...string) *sshParam {
		return &sshParam{
			args:    &sshArgs{Destination: "dest"},
			host:    "myhost",
			port:    "22",
			user:    "myuser",
			proxies: proxies,
		}
	}

	const noJumpHash = "cc2574c1dd762c0b02756b6a09a2c13710d74f81"
	const jumpHash = "7d602da65c0976c65e3f32846ff9793b41252619"
	const lastJumpHash = "7ee756f38d0df9dc5046c8e4595edeef824ba164"
	const ipv6JumpHash = "710d7ae1d5e5d19787e991ab4ae24297353acfc8"

	assertHash := func(proxies []string, supportsJ bool, expected string) {
		t.Helper()
		openSshMajor, openSshMinor, openSshErr = 9, 6, nil
		if !supportsJ {
			openSshMajor, openSshMinor = 9, 5
		}
		result, err := expandTokens("%C", newParam(proxies...), "%CdhijkLlnpru")
		require.Nil(err)
		assert.Equal(expected, result)
	}

	// OpenSSH 9.6 and above: only the host of the last proxy jump is hashed.
	assertHash(nil, true, noJumpHash)
	assertHash([]string{"jump"}, true, jumpHash)
	assertHash([]string{"user@jump"}, true, jumpHash)
	assertHash([]string{"jump:2222"}, true, jumpHash)
	assertHash([]string{"user@jump:2222"}, true, jumpHash)
	// only the last hop takes part in the hash
	assertHash([]string{"jump1", "jump2"}, true, lastJumpHash)
	// IPv6 literal: parse_jump keeps the address without the brackets
	assertHash([]string{"[::1]"}, true, ipv6JumpHash)
	assertHash([]string{"user@[::1]:2222"}, true, ipv6JumpHash)

	// OpenSSH below 9.6: the jump host is not part of the hash at all.
	assertHash(nil, false, noJumpHash)
	assertHash([]string{"jump"}, false, noJumpHash)
	assertHash([]string{"user@jump:2222"}, false, noJumpHash)
}

func TestInvalidUser(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	assertInvalidUser := func(user string) {
		t.Helper()
		_, err := expandTokens("%r", &sshParam{args: &sshArgs{}, user: user}, "%hnpr")
		require.NotNil(err)
		assert.Contains(err.Error(), "contains invalid characters")
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

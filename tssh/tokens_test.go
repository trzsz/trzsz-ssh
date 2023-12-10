/*
MIT License

Copyright (c) 2023 Lonny Wong <lonnywong@qq.com>
Copyright (c) 2023 [Contributors](https://github.com/trzsz/trzsz-ssh/graphs/contributors)

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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExpandTokens(t *testing.T) {
	assert := assert.New(t)
	originalWarning := warning
	defer func() {
		warning = originalWarning
	}()
	var output string
	warning = func(format string, a ...any) {
		output = fmt.Sprintf(format, a...)
	}
	originalGetHostname := getHostname
	defer func() {
		getHostname = originalGetHostname
	}()
	getHostname = func() string { return "myhostname.mydomain.com" }

	args := &sshArgs{
		Destination: "dest",
	}
	param := &loginParam{
		host: "127.0.0.1",
		port: "1337",
		user: "penny",
	}
	assertProxyCommand := func(original, expanded, result string) {
		t.Helper()
		output = ""
		assert.Equal(expanded, expandTokens(original, args, param, "%hnpr"))
		assert.Equal(result, output)
	}

	assertProxyCommand("%%", "%", "")
	assertProxyCommand("%h", "127.0.0.1", "")
	assertProxyCommand("%n", "dest", "")
	assertProxyCommand("%p", "1337", "")
	assertProxyCommand("%r", "penny", "")
	assertProxyCommand("a_%%_%r_%p_%n_%h_Z", "a_%_penny_1337_dest_127.0.0.1_Z", "")

	assertProxyCommand("%l", "%l", "token [%l] in [%l] is not supported")
	assertProxyCommand("a_%h_%C", "a_127.0.0.1_%C", "token [%C] in [a_%h_%C] is not supported")

	assertControlPath := func(original, expanded, result string) {
		t.Helper()
		output = ""
		assert.Equal(expanded, expandTokens(original, args, param, "%CdhikLlnpru"))
		assert.Equal(result, output)
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

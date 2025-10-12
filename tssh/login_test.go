/*
MIT License

Copyright (c) 2023-2025 The Trzsz SSH Authors.

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
)

func TestParseDestination(t *testing.T) {
	assert := assert.New(t)
	assertDestEqual := func(dest, user, host, port string) {
		t.Helper()
		u, h, p := parseDestination(dest)
		assert.Equal(user, u)
		assert.Equal(host, h)
		assert.Equal(port, p)
	}

	assertDestEqual("", "", "", "")
	assertDestEqual("@", "", "", "")
	assertDestEqual(":", "", "", "")
	assertDestEqual("@:", "", "", "")

	assertDestEqual("dest", "", "dest", "")
	assertDestEqual("@dest", "", "dest", "")
	assertDestEqual("dest:", "", "dest", "")
	assertDestEqual("@dest:", "", "dest", "")
	assertDestEqual("user@dest", "user", "dest", "")
	assertDestEqual("dest:1022", "", "dest", "1022")
	assertDestEqual("user@dest:1022", "user", "dest", "1022")

	assertDestEqual("127.0.0.1", "", "127.0.0.1", "")
	assertDestEqual("user@127.0.0.1", "user", "127.0.0.1", "")
	assertDestEqual("127.0.0.1:1022", "", "127.0.0.1", "1022")
	assertDestEqual("user@127.0.0.1:1022", "user", "127.0.0.1", "1022")

	assertDestEqual("::1", "", "::1", "")
	assertDestEqual("user@::1", "user", "::1", "")
	assertDestEqual("[::1]:1022", "", "::1", "1022")
	assertDestEqual("user@[::1]:1022", "user", "::1", "1022")

	assertDestEqual("fe80::6358:bbae:26f8:7859", "", "fe80::6358:bbae:26f8:7859", "")
	assertDestEqual("user@fe80::6358:bbae:26f8:7859", "user", "fe80::6358:bbae:26f8:7859", "")
	assertDestEqual("[fe80::6358:bbae:26f8:7859]:1022", "", "fe80::6358:bbae:26f8:7859", "1022")
	assertDestEqual("user@[fe80::6358:bbae:26f8:7859]:1022", "user", "fe80::6358:bbae:26f8:7859", "1022")
}

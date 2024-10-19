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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDNS(t *testing.T) {

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

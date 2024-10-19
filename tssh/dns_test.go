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

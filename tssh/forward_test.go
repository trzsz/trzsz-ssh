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

func TestParseBindCfg(t *testing.T) {
	assert := assert.New(t)
	assertBindCfgNil := func(arg string, addr *string, port int) {
		t.Helper()
		cfg, err := parseBindCfg(arg)
		assert.Nil(err)
		assert.Equal(&bindCfg{arg, addr, port}, cfg)
	}
	assertBindCfg := func(arg string, addr string, port int) {
		t.Helper()
		assertBindCfgNil(arg, &addr, port)
	}

	assertBindCfgNil("8000", nil, 8000)
	assertBindCfgNil("9000", nil, 9000)
	assertBindCfg(":8000", "", 8000)
	assertBindCfg("*:8001", "*", 8001)

	assertBindCfg("0.0.0.0:8001", "0.0.0.0", 8001)
	assertBindCfg("127.0.0.1:8002", "127.0.0.1", 8002)
	assertBindCfg("localhost:8003", "localhost", 8003)

	assertBindCfg("::1/8001", "::1", 8001)
	assertBindCfg("fe80::6358:bbae:26f8:7859/8002", "fe80::6358:bbae:26f8:7859", 8002)
	assertBindCfg("12a5:00c8:dae6:bd0a:8312:07f8:bc94:a1d9/8003", "12a5:00c8:dae6:bd0a:8312:07f8:bc94:a1d9", 8003)

	assertBindCfg("[::1]:8001", "::1", 8001)
	assertBindCfg("[fe80::6358:bbae:26f8:7859]:8002", "fe80::6358:bbae:26f8:7859", 8002)
	assertBindCfg("[12a5:00c8:dae6:bd0a:8312:07f8:bc94:a1d9]:8003", "12a5:00c8:dae6:bd0a:8312:07f8:bc94:a1d9", 8003)

	assertBindCfg("/bind_socket", "/bind_socket", -1)
	assertBindCfg("/bind/socket", "/bind/socket", -1)

	assertCfgError := func(arg, errMsg string) {
		t.Helper()
		_, err := parseBindCfg(arg)
		assert.NotNil(err)
		assert.Contains(err.Error(), errMsg)
	}

	assertCfgError("A8000", "invalid bind specification: A8000")
	assertCfgError("8000B", "invalid bind specification: 8000B")
	assertCfgError("::8000", "invalid bind specification: ::8000")
	assertCfgError("::1:8000", "invalid bind specification: ::1:8000")
	assertCfgError("[:\t:1]:8000", "invalid bind specification: [:\t:1]:8000")
	assertCfgError("A[::1]:8000", "invalid bind specification: A[::1]:8000")
	assertCfgError("[::1]:8000B", "invalid bind specification: [::1]:8000B")
	assertCfgError("[[::1]:8000", "invalid bind specification: [[::1]:8000")
	assertCfgError("[::1]]:8000", "invalid bind specification: [::1]]:8000")
	assertCfgError("localhost::8000", "invalid bind specification: localhost::8000")
	assertCfgError(":127.0.0.1:8000", "invalid bind specification: :127.0.0.1:8000")
}

func TestParseForwardCfg(t *testing.T) {
	assert := assert.New(t)
	assertForwardCfgNil := func(arg string, bindAddr *string, bindPort int, destHost string, destPort int) {
		t.Helper()
		cfg, err := parseForwardCfg(arg)
		assert.Nil(err)
		assert.Equal(&forwardCfg{arg, bindAddr, bindPort, destHost, destPort}, cfg)
	}
	assertForwardCfg := func(arg string, bindAddr string, bindPort int, destHost string, destPort int) {
		t.Helper()
		assertForwardCfgNil(arg, &bindAddr, bindPort, destHost, destPort)
	}

	assertForwardCfgNil("8000 localhost:9000", nil, 8000, "localhost", 9000)
	assertForwardCfgNil("8001 127.0.0.1:9001", nil, 8001, "127.0.0.1", 9001)
	assertForwardCfgNil("8000 ::1/9000", nil, 8000, "::1", 9000)
	assertForwardCfgNil("8000 [::1]:9000", nil, 8000, "::1", 9000)
	assertForwardCfgNil("8000 fe80::6358:bbae:26f8:7859/9000", nil, 8000, "fe80::6358:bbae:26f8:7859", 9000)
	assertForwardCfgNil("8000 [fe80::6358:bbae:26f8:7859]:9000", nil, 8000, "fe80::6358:bbae:26f8:7859", 9000)

	assertForwardCfg(":8001 localhost:9001", "", 8001, "localhost", 9001)
	assertForwardCfg(":8002 [::1]:9002", "", 8002, "::1", 9002)
	assertForwardCfg("*:8003 127.0.0.1:9003", "*", 8003, "127.0.0.1", 9003)
	assertForwardCfg("*:8004 [fe80::6358:bbae:26f8:7859]:9004", "*", 8004, "fe80::6358:bbae:26f8:7859", 9004)

	assertForwardCfg("127.0.0.1:8001\tlocalhost:9001", "127.0.0.1", 8001, "localhost", 9001)
	assertForwardCfg("localhost:8002\t127.0.0.1:9002", "localhost", 8002, "127.0.0.1", 9002)
	assertForwardCfg("127.0.0.1:8003\t[::1]:9003", "127.0.0.1", 8003, "::1", 9003)
	assertForwardCfg("localhost:8004\t[fe80::6358:bbae:26f8:7859]:9004", "localhost", 8004, "fe80::6358:bbae:26f8:7859", 9004)
	assertForwardCfg("[::1]:8005\tlocalhost:9005", "::1", 8005, "localhost", 9005)
	assertForwardCfg("[fe80::6358:bbae:26f8:7859]:8006\t127.0.0.1:9006", "fe80::6358:bbae:26f8:7859", 8006, "127.0.0.1", 9006)
	assertForwardCfg("[12a5:00c8:dae6:bd0a:8312:07f8:bc94:a1d9]:8007\t[::1]:9007", "12a5:00c8:dae6:bd0a:8312:07f8:bc94:a1d9", 8007, "::1", 9007)

	assertForwardCfg("127.0.0.1/8001 \t localhost/9001", "127.0.0.1", 8001, "localhost", 9001)
	assertForwardCfg("localhost/8002 \t 127.0.0.1/9002", "localhost", 8002, "127.0.0.1", 9002)
	assertForwardCfg("127.0.0.1/8003 \t ::1/9003", "127.0.0.1", 8003, "::1", 9003)
	assertForwardCfg("localhost/8004 \t fe80::6358:bbae:26f8:7859/9004", "localhost", 8004, "fe80::6358:bbae:26f8:7859", 9004)
	assertForwardCfg("::1/8005 \t localhost/9005", "::1", 8005, "localhost", 9005)
	assertForwardCfg("fe80::6358:bbae:26f8:7859/8006 \t 127.0.0.1/9006", "fe80::6358:bbae:26f8:7859", 8006, "127.0.0.1", 9006)
	assertForwardCfg("12a5:00c8:dae6:bd0a:8312:07f8:bc94:a1d9/8007 \t ::1/9007", "12a5:00c8:dae6:bd0a:8312:07f8:bc94:a1d9", 8007, "::1", 9007)
	assertForwardCfg("/8008 \t localhost/9008", "", 8008, "localhost", 9008)
	assertForwardCfg("*/8009 \t fe80::6358:bbae:26f8:7859/9009", "*", 8009, "fe80::6358:bbae:26f8:7859", 9009)

	assertForwardCfgNil("8000 /forward_socket", nil, 8000, "/forward_socket", -1)
	assertForwardCfgNil("8000 \t /forward/socket", nil, 8000, "/forward/socket", -1)
	assertForwardCfg("localhost:8001 /forward_socket", "localhost", 8001, "/forward_socket", -1)
	assertForwardCfg("localhost:8001 \t /forward/socket", "localhost", 8001, "/forward/socket", -1)
	assertForwardCfg("/bind_socket localhost:9001", "/bind_socket", -1, "localhost", 9001)
	assertForwardCfg("/bind/socket \t localhost:9002", "/bind/socket", -1, "localhost", 9002)
	assertForwardCfg("/bind_socket /forward_socket", "/bind_socket", -1, "/forward_socket", -1)
	assertForwardCfg("/bind/socket \t /forward/socket", "/bind/socket", -1, "/forward/socket", -1)

	assertArgError := func(arg, errMsg string) {
		t.Helper()
		_, err := parseForwardCfg(arg)
		assert.NotNil(err)
		assert.Contains(err.Error(), errMsg)
	}

	assertArgError("::1:8000 localhost:9000", "invalid forward config: ::1:8000 localhost:9000")
	assertArgError("A[::1]:8000 localhost:9000", "invalid forward config: A[::1]:8000 localhost:9000")
	assertArgError("[::1]:8000 localhost:9000B", "invalid forward config: [::1]:8000 localhost:9000B")
	assertArgError("[[::1]:8000 localhost:9000", "invalid forward config: [[::1]:8000 localhost:9000")
	assertArgError("[::1]]:8000 localhost:9000", "invalid forward config: [::1]]:8000 localhost:9000")
	assertArgError("[:\t:1]:8000 localhost:9000", "invalid forward config: [:\t:1]:8000 localhost:9000")

	assertArgError("127.0.0.1:8000 ::1:9000", "invalid forward config: 127.0.0.1:8000 ::1:9000")
	assertArgError("127.0.0.1:A8000 [::1]:9000", "invalid forward config: 127.0.0.1:A8000 [::1]:9000")
	assertArgError("127.0.0.1:8000 [::1]:9000B", "invalid forward config: 127.0.0.1:8000 [::1]:9000B")
	assertArgError("127.0.0.1:8000 [[::1]:9000", "invalid forward config: 127.0.0.1:8000 [[::1]:9000")
	assertArgError("127.0.0.1:8000 [::1]]:9000", "invalid forward config: 127.0.0.1:8000 [::1]]:9000")
	assertArgError("127.0.0.1:8000 [:\t:1]:9000", "invalid forward config: 127.0.0.1:8000 [:\t:1]:9000")
}

func TestParseForwardArg(t *testing.T) {
	assert := assert.New(t)
	assertForwardCfgNil := func(arg string, bindAddr *string, bindPort int, destHost string, destPort int) {
		t.Helper()
		cfg, err := parseForwardArg(arg)
		assert.Nil(err)
		assert.Equal(&forwardCfg{arg, bindAddr, bindPort, destHost, destPort}, cfg)
	}
	assertForwardCfg := func(arg string, bindAddr string, bindPort int, destHost string, destPort int) {
		t.Helper()
		assertForwardCfgNil(arg, &bindAddr, bindPort, destHost, destPort)
	}

	assertForwardCfgNil("8000:localhost:9000", nil, 8000, "localhost", 9000)
	assertForwardCfgNil("8001:127.0.0.1:9001", nil, 8001, "127.0.0.1", 9001)
	assertForwardCfgNil("8000/::1/9000", nil, 8000, "::1", 9000)
	assertForwardCfgNil("8000:[::1]:9000", nil, 8000, "::1", 9000)
	assertForwardCfgNil("8000/fe80::6358:bbae:26f8:7859/9000", nil, 8000, "fe80::6358:bbae:26f8:7859", 9000)
	assertForwardCfgNil("8000:[fe80::6358:bbae:26f8:7859]:9000", nil, 8000, "fe80::6358:bbae:26f8:7859", 9000)

	assertForwardCfg(":8001:localhost:9001", "", 8001, "localhost", 9001)
	assertForwardCfg(":8002:[::1]:9002", "", 8002, "::1", 9002)
	assertForwardCfg("*:8003:127.0.0.1:9003", "*", 8003, "127.0.0.1", 9003)
	assertForwardCfg("*:8004:[fe80::6358:bbae:26f8:7859]:9004", "*", 8004, "fe80::6358:bbae:26f8:7859", 9004)

	assertForwardCfg("127.0.0.1:8001:localhost:9001", "127.0.0.1", 8001, "localhost", 9001)
	assertForwardCfg("localhost:8002:127.0.0.1:9002", "localhost", 8002, "127.0.0.1", 9002)
	assertForwardCfg("127.0.0.1:8003:[::1]:9003", "127.0.0.1", 8003, "::1", 9003)
	assertForwardCfg("localhost:8004:[fe80::6358:bbae:26f8:7859]:9004", "localhost", 8004, "fe80::6358:bbae:26f8:7859", 9004)
	assertForwardCfg("[::1]:8005:localhost:9005", "::1", 8005, "localhost", 9005)
	assertForwardCfg("[fe80::6358:bbae:26f8:7859]:8006:127.0.0.1:9006", "fe80::6358:bbae:26f8:7859", 8006, "127.0.0.1", 9006)
	assertForwardCfg("[12a5:00c8:dae6:bd0a:8312:07f8:bc94:a1d9]:8007:[::1]:9007", "12a5:00c8:dae6:bd0a:8312:07f8:bc94:a1d9", 8007, "::1", 9007)

	assertForwardCfg("127.0.0.1/8001/localhost/9001", "127.0.0.1", 8001, "localhost", 9001)
	assertForwardCfg("localhost/8002/127.0.0.1/9002", "localhost", 8002, "127.0.0.1", 9002)
	assertForwardCfg("127.0.0.1/8003/::1/9003", "127.0.0.1", 8003, "::1", 9003)
	assertForwardCfg("localhost/8004/fe80::6358:bbae:26f8:7859/9004", "localhost", 8004, "fe80::6358:bbae:26f8:7859", 9004)
	assertForwardCfg("::1/8005/localhost/9005", "::1", 8005, "localhost", 9005)
	assertForwardCfg("fe80::6358:bbae:26f8:7859/8006/127.0.0.1/9006", "fe80::6358:bbae:26f8:7859", 8006, "127.0.0.1", 9006)
	assertForwardCfg("12a5:00c8:dae6:bd0a:8312:07f8:bc94:a1d9/8007/::1/9007", "12a5:00c8:dae6:bd0a:8312:07f8:bc94:a1d9", 8007, "::1", 9007)
	assertForwardCfg("/8008/localhost/9008", "", 8008, "localhost", 9008)
	assertForwardCfg("*/8009/fe80::6358:bbae:26f8:7859/9009", "*", 8009, "fe80::6358:bbae:26f8:7859", 9009)

	assertForwardCfgNil("8000:/forward_socket", nil, 8000, "/forward_socket", -1)
	assertForwardCfgNil("8000:/forward/socket", nil, 8000, "/forward/socket", -1)
	assertForwardCfg("localhost:8001:/forward_socket", "localhost", 8001, "/forward_socket", -1)
	assertForwardCfg("localhost:8001:/forward/socket", "localhost", 8001, "/forward/socket", -1)
	assertForwardCfg("/bind_socket:localhost:9001", "/bind_socket", -1, "localhost", 9001)
	assertForwardCfg("/bind/socket:localhost:9002", "/bind/socket", -1, "localhost", 9002)
	assertForwardCfg("/bind_socket:/forward_socket", "/bind_socket", -1, "/forward_socket", -1)
	assertForwardCfg("/bind/socket:/forward/socket", "/bind/socket", -1, "/forward/socket", -1)

	assertArgError := func(arg, errMsg string) {
		t.Helper()
		_, err := parseForwardArg(arg)
		assert.NotNil(err)
		assert.Contains(err.Error(), errMsg)
	}

	assertArgError("::1:8000:localhost:9000", "invalid forward specification: ::1:8000:localhost:9000")
	assertArgError("A[::1]:8000:localhost:9000", "invalid forward specification: A[::1]:8000:localhost:9000")
	assertArgError("[::1]:8000:localhost:9000B", "invalid forward specification: [::1]:8000:localhost:9000B")
	assertArgError("[[::1]:8000:localhost:9000", "invalid forward specification: [[::1]:8000:localhost:9000")
	assertArgError("[::1]]:8000:localhost:9000", "invalid forward specification: [::1]]:8000:localhost:9000")
	assertArgError("[:\t:1]:8000:localhost:9000", "invalid forward specification: [:\t:1]:8000:localhost:9000")

	assertArgError("127.0.0.1:8000:::1:9000", "invalid forward specification: 127.0.0.1:8000:::1:9000")
	assertArgError("127.0.0.1:A8000:[::1]:9000", "invalid forward specification: 127.0.0.1:A8000:[::1]:9000")
	assertArgError("127.0.0.1:8000:[::1]:9000B", "invalid forward specification: 127.0.0.1:8000:[::1]:9000B")
	assertArgError("127.0.0.1:8000:[[::1]:9000", "invalid forward specification: 127.0.0.1:8000:[[::1]:9000")
	assertArgError("127.0.0.1:8000:[::1]]:9000", "invalid forward specification: 127.0.0.1:8000:[::1]]:9000")
	assertArgError("127.0.0.1:8000:[:\t:1]:9000", "invalid forward specification: 127.0.0.1:8000:[:\t:1]:9000")
}

func TestConvertSshTime(t *testing.T) {
	assert := assert.New(t)
	assertTimeEqual := func(time string, expected int) {
		t.Helper()
		seconds, err := convertSshTime(time)
		assert.Nil(err)
		assert.Equal(expected, seconds)
	}
	assertTimeEqual("0", 0)
	assertTimeEqual("0s", 0)
	assertTimeEqual("0W", 0)
	assertTimeEqual("1", 1)
	assertTimeEqual("1S", 1)
	assertTimeEqual("90m", 5400)
	assertTimeEqual("1h30m", 5400)
	assertTimeEqual("2d", 172800)
	assertTimeEqual("1w", 604800)
	assertTimeEqual("1W2d3h4m5", 788645)
}

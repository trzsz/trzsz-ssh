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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseBindCfg(t *testing.T) {
	assert := assert.New(t)
	assertBindCfg := func(arg string, expected *bindCfg) {
		t.Helper()
		cfg, err := parseBindCfg(arg)
		assert.Nil(err)
		assert.Equal(expected, cfg)
	}
	newBindArg := func(addr string, port int) *bindCfg {
		return &bindCfg{&addr, port}
	}

	assertBindCfg("8000", &bindCfg{nil, 8000})
	assertBindCfg("9000", &bindCfg{nil, 9000})
	assertBindCfg(":8000", newBindArg("", 8000))
	assertBindCfg("*:8001", newBindArg("*", 8001))

	assertBindCfg("0.0.0.0:8001", newBindArg("0.0.0.0", 8001))
	assertBindCfg("127.0.0.1:8002", newBindArg("127.0.0.1", 8002))
	assertBindCfg("localhost:8003", newBindArg("localhost", 8003))

	assertBindCfg("::1/8001", newBindArg("::1", 8001))
	assertBindCfg("fe80::6358:bbae:26f8:7859/8002", newBindArg("fe80::6358:bbae:26f8:7859", 8002))
	assertBindCfg("12a5:00c8:dae6:bd0a:8312:07f8:bc94:a1d9/8003", newBindArg("12a5:00c8:dae6:bd0a:8312:07f8:bc94:a1d9", 8003))

	assertBindCfg("[::1]:8001", newBindArg("::1", 8001))
	assertBindCfg("[fe80::6358:bbae:26f8:7859]:8002", newBindArg("fe80::6358:bbae:26f8:7859", 8002))
	assertBindCfg("[12a5:00c8:dae6:bd0a:8312:07f8:bc94:a1d9]:8003", newBindArg("12a5:00c8:dae6:bd0a:8312:07f8:bc94:a1d9", 8003))

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
	assertForwardCfg := func(arg string, expected *forwardCfg) {
		t.Helper()
		cfg, err := parseForwardCfg(arg)
		assert.Nil(err)
		assert.Equal(expected, cfg)
	}
	newForwardCfg := func(bindAddr string, bindPort int, destHost string, destPort int) *forwardCfg {
		return &forwardCfg{&bindAddr, bindPort, destHost, destPort}
	}

	assertForwardCfg("8000 localhost:9000", &forwardCfg{nil, 8000, "localhost", 9000})
	assertForwardCfg("8001 127.0.0.1:9001", &forwardCfg{nil, 8001, "127.0.0.1", 9001})
	assertForwardCfg("8000 ::1/9000", &forwardCfg{nil, 8000, "::1", 9000})
	assertForwardCfg("8000 [::1]:9000", &forwardCfg{nil, 8000, "::1", 9000})
	assertForwardCfg("8000 fe80::6358:bbae:26f8:7859/9000", &forwardCfg{nil, 8000, "fe80::6358:bbae:26f8:7859", 9000})
	assertForwardCfg("8000 [fe80::6358:bbae:26f8:7859]:9000", &forwardCfg{nil, 8000, "fe80::6358:bbae:26f8:7859", 9000})

	assertForwardCfg(":8001 localhost:9001", newForwardCfg("", 8001, "localhost", 9001))
	assertForwardCfg(":8002 [::1]:9002", newForwardCfg("", 8002, "::1", 9002))
	assertForwardCfg("*:8003 127.0.0.1:9003", newForwardCfg("*", 8003, "127.0.0.1", 9003))
	assertForwardCfg("*:8004 [fe80::6358:bbae:26f8:7859]:9004", newForwardCfg("*", 8004, "fe80::6358:bbae:26f8:7859", 9004))

	assertForwardCfg("127.0.0.1:8001\tlocalhost:9001", newForwardCfg("127.0.0.1", 8001, "localhost", 9001))
	assertForwardCfg("localhost:8002\t127.0.0.1:9002", newForwardCfg("localhost", 8002, "127.0.0.1", 9002))
	assertForwardCfg("127.0.0.1:8003\t[::1]:9003", newForwardCfg("127.0.0.1", 8003, "::1", 9003))
	assertForwardCfg("localhost:8004\t[fe80::6358:bbae:26f8:7859]:9004", newForwardCfg("localhost", 8004, "fe80::6358:bbae:26f8:7859", 9004))
	assertForwardCfg("[::1]:8005\tlocalhost:9005", newForwardCfg("::1", 8005, "localhost", 9005))
	assertForwardCfg("[fe80::6358:bbae:26f8:7859]:8006\t127.0.0.1:9006", newForwardCfg("fe80::6358:bbae:26f8:7859", 8006, "127.0.0.1", 9006))
	assertForwardCfg("[12a5:00c8:dae6:bd0a:8312:07f8:bc94:a1d9]:8007\t[::1]:9007", newForwardCfg("12a5:00c8:dae6:bd0a:8312:07f8:bc94:a1d9", 8007, "::1", 9007))

	assertForwardCfg("127.0.0.1/8001 \t localhost/9001", newForwardCfg("127.0.0.1", 8001, "localhost", 9001))
	assertForwardCfg("localhost/8002 \t 127.0.0.1/9002", newForwardCfg("localhost", 8002, "127.0.0.1", 9002))
	assertForwardCfg("127.0.0.1/8003 \t ::1/9003", newForwardCfg("127.0.0.1", 8003, "::1", 9003))
	assertForwardCfg("localhost/8004 \t fe80::6358:bbae:26f8:7859/9004", newForwardCfg("localhost", 8004, "fe80::6358:bbae:26f8:7859", 9004))
	assertForwardCfg("::1/8005 \t localhost/9005", newForwardCfg("::1", 8005, "localhost", 9005))
	assertForwardCfg("fe80::6358:bbae:26f8:7859/8006 \t 127.0.0.1/9006", newForwardCfg("fe80::6358:bbae:26f8:7859", 8006, "127.0.0.1", 9006))
	assertForwardCfg("12a5:00c8:dae6:bd0a:8312:07f8:bc94:a1d9/8007 \t ::1/9007", newForwardCfg("12a5:00c8:dae6:bd0a:8312:07f8:bc94:a1d9", 8007, "::1", 9007))
	assertForwardCfg("/8008 \t localhost/9008", newForwardCfg("", 8008, "localhost", 9008))
	assertForwardCfg("*/8009 \t fe80::6358:bbae:26f8:7859/9009", newForwardCfg("*", 8009, "fe80::6358:bbae:26f8:7859", 9009))

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
	assertForwardCfg := func(arg string, expected *forwardCfg) {
		t.Helper()
		cfg, err := parseForwardArg(arg)
		assert.Nil(err)
		assert.Equal(expected, cfg)
	}
	newForwardCfg := func(bindAddr string, bindPort int, destHost string, destPort int) *forwardCfg {
		return &forwardCfg{&bindAddr, bindPort, destHost, destPort}
	}

	assertForwardCfg("8000:localhost:9000", &forwardCfg{nil, 8000, "localhost", 9000})
	assertForwardCfg("8001:127.0.0.1:9001", &forwardCfg{nil, 8001, "127.0.0.1", 9001})
	assertForwardCfg("8000/::1/9000", &forwardCfg{nil, 8000, "::1", 9000})
	assertForwardCfg("8000:[::1]:9000", &forwardCfg{nil, 8000, "::1", 9000})
	assertForwardCfg("8000/fe80::6358:bbae:26f8:7859/9000", &forwardCfg{nil, 8000, "fe80::6358:bbae:26f8:7859", 9000})
	assertForwardCfg("8000:[fe80::6358:bbae:26f8:7859]:9000", &forwardCfg{nil, 8000, "fe80::6358:bbae:26f8:7859", 9000})

	assertForwardCfg(":8001:localhost:9001", newForwardCfg("", 8001, "localhost", 9001))
	assertForwardCfg(":8002:[::1]:9002", newForwardCfg("", 8002, "::1", 9002))
	assertForwardCfg("*:8003:127.0.0.1:9003", newForwardCfg("*", 8003, "127.0.0.1", 9003))
	assertForwardCfg("*:8004:[fe80::6358:bbae:26f8:7859]:9004", newForwardCfg("*", 8004, "fe80::6358:bbae:26f8:7859", 9004))

	assertForwardCfg("127.0.0.1:8001:localhost:9001", newForwardCfg("127.0.0.1", 8001, "localhost", 9001))
	assertForwardCfg("localhost:8002:127.0.0.1:9002", newForwardCfg("localhost", 8002, "127.0.0.1", 9002))
	assertForwardCfg("127.0.0.1:8003:[::1]:9003", newForwardCfg("127.0.0.1", 8003, "::1", 9003))
	assertForwardCfg("localhost:8004:[fe80::6358:bbae:26f8:7859]:9004", newForwardCfg("localhost", 8004, "fe80::6358:bbae:26f8:7859", 9004))
	assertForwardCfg("[::1]:8005:localhost:9005", newForwardCfg("::1", 8005, "localhost", 9005))
	assertForwardCfg("[fe80::6358:bbae:26f8:7859]:8006:127.0.0.1:9006", newForwardCfg("fe80::6358:bbae:26f8:7859", 8006, "127.0.0.1", 9006))
	assertForwardCfg("[12a5:00c8:dae6:bd0a:8312:07f8:bc94:a1d9]:8007:[::1]:9007", newForwardCfg("12a5:00c8:dae6:bd0a:8312:07f8:bc94:a1d9", 8007, "::1", 9007))

	assertForwardCfg("127.0.0.1/8001/localhost/9001", newForwardCfg("127.0.0.1", 8001, "localhost", 9001))
	assertForwardCfg("localhost/8002/127.0.0.1/9002", newForwardCfg("localhost", 8002, "127.0.0.1", 9002))
	assertForwardCfg("127.0.0.1/8003/::1/9003", newForwardCfg("127.0.0.1", 8003, "::1", 9003))
	assertForwardCfg("localhost/8004/fe80::6358:bbae:26f8:7859/9004", newForwardCfg("localhost", 8004, "fe80::6358:bbae:26f8:7859", 9004))
	assertForwardCfg("::1/8005/localhost/9005", newForwardCfg("::1", 8005, "localhost", 9005))
	assertForwardCfg("fe80::6358:bbae:26f8:7859/8006/127.0.0.1/9006", newForwardCfg("fe80::6358:bbae:26f8:7859", 8006, "127.0.0.1", 9006))
	assertForwardCfg("12a5:00c8:dae6:bd0a:8312:07f8:bc94:a1d9/8007/::1/9007", newForwardCfg("12a5:00c8:dae6:bd0a:8312:07f8:bc94:a1d9", 8007, "::1", 9007))
	assertForwardCfg("/8008/localhost/9008", newForwardCfg("", 8008, "localhost", 9008))
	assertForwardCfg("*/8009/fe80::6358:bbae:26f8:7859/9009", newForwardCfg("*", 8009, "fe80::6358:bbae:26f8:7859", 9009))

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

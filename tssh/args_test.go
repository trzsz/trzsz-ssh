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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trzsz/go-arg"
)

func TestSshArgs(t *testing.T) {
	assert := assert.New(t)
	assertArgsEqual := func(cmdline string, expectedArg sshArgs) {
		t.Helper()
		var args sshArgs
		p, err := arg.NewParser(arg.Config{}, &args)
		assert.Nil(err)
		if cmdline == "" {
			err = p.Parse(nil)
		} else {
			err = p.Parse(strings.Split(cmdline, " "))
		}
		assert.Nil(err)
		assert.Equal(expectedArg, args)
	}

	assertArgsEqual("", sshArgs{})
	assertArgsEqual("-V", sshArgs{Ver: true})
	assertArgsEqual("-A", sshArgs{ForwardAgent: true})
	assertArgsEqual("-a", sshArgs{NoForwardAgent: true})
	assertArgsEqual("-T", sshArgs{DisableTTY: true})
	assertArgsEqual("-t", sshArgs{ForceTTY: true})
	assertArgsEqual("-g", sshArgs{Gateway: true})
	assertArgsEqual("-f", sshArgs{Background: true})
	assertArgsEqual("-N", sshArgs{NoCommand: true})
	assertArgsEqual("-gfN -T", sshArgs{Gateway: true, Background: true, NoCommand: true, DisableTTY: true})

	assertArgsEqual("-p1022", sshArgs{Port: 1022})
	assertArgsEqual("-p 2049", sshArgs{Port: 2049})
	assertArgsEqual("-luser", sshArgs{LoginName: "user"})
	assertArgsEqual("-l loginName", sshArgs{LoginName: "loginName"})
	assertArgsEqual("-i id_rsa", sshArgs{Identity: multiStr{values: []string{"id_rsa"}}})
	assertArgsEqual("-i ./id_rsa -i /tmp/id_ed25519",
		sshArgs{Identity: multiStr{[]string{"./id_rsa", "/tmp/id_ed25519"}}})
	assertArgsEqual("-Fcfg", sshArgs{ConfigFile: "cfg"})
	assertArgsEqual("-F /path/to/cfg", sshArgs{ConfigFile: "/path/to/cfg"})
	assertArgsEqual("-Jjump", sshArgs{ProxyJump: "jump"})
	assertArgsEqual("-J abc,def", sshArgs{ProxyJump: "abc,def"})
	assertArgsEqual("-o RemoteCommand=none -oServerAliveInterval=5",
		sshArgs{Option: sshOption{map[string]string{"remotecommand": "none", "serveraliveinterval": "5"}}})

	newBindCfg := func(addr string, port int) *bindCfg {
		return &bindCfg{&addr, port}
	}
	assertArgsEqual("-D 8000", sshArgs{DynamicForward: bindArgs{[]*bindCfg{{nil, 8000}}}})
	assertArgsEqual("-D 127.0.0.1:8002", sshArgs{DynamicForward: bindArgs{[]*bindCfg{newBindCfg("127.0.0.1", 8002)}}})
	assertArgsEqual("-D [fe80::6358:bbae:26f8:7859]:8003",
		sshArgs{DynamicForward: bindArgs{[]*bindCfg{newBindCfg("fe80::6358:bbae:26f8:7859", 8003)}}})
	assertArgsEqual("-D :8004 -D *:8005 -D ::1/8006",
		sshArgs{DynamicForward: bindArgs{[]*bindCfg{newBindCfg("", 8004), newBindCfg("*", 8005), newBindCfg("::1", 8006)}}})

	newForwardCfg := func(bindAddr string, bindPort int, destHost string, destPort int) *forwardCfg {
		return &forwardCfg{&bindAddr, bindPort, destHost, destPort}
	}
	assertArgsEqual("-L 127.0.0.1:8001:[::1]:9001",
		sshArgs{LocalForward: forwardArgs{[]*forwardCfg{newForwardCfg("127.0.0.1", 8001, "::1", 9001)}}})
	assertArgsEqual("-L ::1/8002/localhost/9002",
		sshArgs{LocalForward: forwardArgs{[]*forwardCfg{newForwardCfg("::1", 8002, "localhost", 9002)}}})
	assertArgsEqual("-L 8003:0.0.0.0:9003 -L ::/8004/::1/9004", sshArgs{LocalForward: forwardArgs{
		[]*forwardCfg{{nil, 8003, "0.0.0.0", 9003}, newForwardCfg("::", 8004, "::1", 9004)}}})
	assertArgsEqual("-R :8001:[fe80::6358:bbae:26f8:7859]:9001",
		sshArgs{RemoteForward: forwardArgs{[]*forwardCfg{newForwardCfg("", 8001, "fe80::6358:bbae:26f8:7859", 9001)}}})
	assertArgsEqual("-R /8002/127.0.0.1/9002",
		sshArgs{RemoteForward: forwardArgs{[]*forwardCfg{newForwardCfg("", 8002, "127.0.0.1", 9002)}}})
	assertArgsEqual("-R 8003/::1/9003 -R *:8004:[fe80::6358:bbae:26f8:7859]:9004", sshArgs{RemoteForward: forwardArgs{
		[]*forwardCfg{{nil, 8003, "::1", 9003}, newForwardCfg("*", 8004, "fe80::6358:bbae:26f8:7859", 9004)}}})

	assertArgsEqual("--reconnect", sshArgs{Reconnect: true})
	assertArgsEqual("--dragfile", sshArgs{DragFile: true})
	assertArgsEqual("--tracelog", sshArgs{TraceLog: true})
	assertArgsEqual("--relay", sshArgs{Relay: true})
	assertArgsEqual("--debug", sshArgs{Debug: true})

	assertArgsEqual("dest", sshArgs{Destination: "dest"})
	assertArgsEqual("dest cmd", sshArgs{Destination: "dest", Command: "cmd"})
	assertArgsEqual("dest cmd arg1", sshArgs{Destination: "dest", Command: "cmd", Argument: []string{"arg1"}})
	assertArgsEqual("dest cmd arg1 arg2", sshArgs{Destination: "dest", Command: "cmd", Argument: []string{"arg1", "arg2"}})

	assertArgsEqual("-tp222 -oRemoteCommand=none -i~/.ssh/id_rsa -o ServerAliveCountMax=2 dest cmd arg1 arg2",
		sshArgs{ForceTTY: true, Port: 222, Identity: multiStr{values: []string{"~/.ssh/id_rsa"}},
			Option:      sshOption{map[string]string{"remotecommand": "none", "serveralivecountmax": "2"}},
			Destination: "dest", Command: "cmd", Argument: []string{"arg1", "arg2"}})

	assertArgsError := func(cmdline, errMsg string) {
		t.Helper()
		var args sshArgs
		p, err := arg.NewParser(arg.Config{}, &args)
		assert.Nil(err)
		err = p.Parse(strings.Split(cmdline, " "))
		assert.NotNil(err)
		assert.Contains(err.Error(), errMsg)
	}

	assertArgsError("-D", "missing value for -D")
	assertArgsError("-L", "missing value for -L")
	assertArgsError("-R", "missing value for -R")
}

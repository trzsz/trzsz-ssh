/*
MIT License

Copyright (c) 2023 Lonny Wong <lonnywong@qq.com>

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
			err = p.Parse(strings.Fields(cmdline))
		}
		assert.Nil(err)
		assert.Equal(expectedArg, args)
	}

	assertArgsEqual("", sshArgs{})
	assertArgsEqual("-V", sshArgs{Ver: true})
	assertArgsEqual("-T", sshArgs{DisableTTY: true})
	assertArgsEqual("-t", sshArgs{ForceTTY: true})

	assertArgsEqual("-p1022", sshArgs{Port: 1022})
	assertArgsEqual("-p 2049", sshArgs{Port: 2049})
	assertArgsEqual("-i id_rsa", sshArgs{Identity: multiStr{values: []string{"id_rsa"}}})
	assertArgsEqual("-i ./id_rsa -i /tmp/id_ed25519",
		sshArgs{Identity: multiStr{[]string{"./id_rsa", "/tmp/id_ed25519"}}})
	assertArgsEqual("-Jjump", sshArgs{ProxyJump: "jump"})
	assertArgsEqual("-J abc,def", sshArgs{ProxyJump: "abc,def"})
	assertArgsEqual("-o RemoteCommand=none -oServerAliveInterval=5",
		sshArgs{Option: sshOption{map[string]string{"remotecommand": "none", "serveraliveinterval": "5"}}})

	assertArgsEqual("--dragfile", sshArgs{DragFile: true})
	assertArgsEqual("--tracelog", sshArgs{TraceLog: true})
	assertArgsEqual("--relay", sshArgs{Relay: true})

	assertArgsEqual("dest", sshArgs{Destination: "dest"})
	assertArgsEqual("dest cmd", sshArgs{Destination: "dest", Command: "cmd"})
	assertArgsEqual("dest cmd arg1", sshArgs{Destination: "dest", Command: "cmd", Argument: []string{"arg1"}})
	assertArgsEqual("dest cmd arg1 arg2", sshArgs{Destination: "dest", Command: "cmd", Argument: []string{"arg1", "arg2"}})

	assertArgsEqual("-tp222 -oRemoteCommand=none -i~/.ssh/id_rsa -o ServerAliveCountMax=2 dest cmd arg1 arg2",
		sshArgs{ForceTTY: true, Port: 222, Identity: multiStr{values: []string{"~/.ssh/id_rsa"}},
			Option:      sshOption{map[string]string{"remotecommand": "none", "serveralivecountmax": "2"}},
			Destination: "dest", Command: "cmd", Argument: []string{"arg1", "arg2"}})
}

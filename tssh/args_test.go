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
	assertArgsEqual("-4", sshArgs{IPv4Only: true})
	assertArgsEqual("-6", sshArgs{IPv6Only: true})
	assertArgsEqual("-g", sshArgs{Gateway: true})
	assertArgsEqual("-f", sshArgs{Background: true})
	assertArgsEqual("-N", sshArgs{NoCommand: true})
	assertArgsEqual("-gfN -T", sshArgs{Gateway: true, Background: true, NoCommand: true, DisableTTY: true})

	assertArgsEqual("-X", sshArgs{X11Untrusted: true})
	assertArgsEqual("-x", sshArgs{NoX11Forward: true})
	assertArgsEqual("-Y", sshArgs{X11Trusted: true})

	assertArgsEqual("-p1022", sshArgs{Port: 1022})
	assertArgsEqual("-p 2049", sshArgs{Port: 2049})
	assertArgsEqual("-luser", sshArgs{LoginName: "user"})
	assertArgsEqual("-l loginName", sshArgs{LoginName: "loginName"})
	assertArgsEqual("-i id_rsa", sshArgs{Identity: multiStr{values: []string{"id_rsa"}}})
	assertArgsEqual("-i ./id_rsa -i /tmp/id_ed25519",
		sshArgs{Identity: multiStr{[]string{"./id_rsa", "/tmp/id_ed25519"}}})
	assertArgsEqual("-c+aes128-cbc", sshArgs{CipherSpec: "+aes128-cbc"})
	assertArgsEqual("-c ^aes128-cbc,3des-cbc", sshArgs{CipherSpec: "^aes128-cbc,3des-cbc"})
	assertArgsEqual("-Fcfg", sshArgs{ConfigFile: "cfg"})
	assertArgsEqual("-F /path/to/cfg", sshArgs{ConfigFile: "/path/to/cfg"})
	assertArgsEqual("-Jjump", sshArgs{ProxyJump: "jump"})
	assertArgsEqual("-J abc,def", sshArgs{ProxyJump: "abc,def"})
	assertArgsEqual("-o RemoteCommand=none -oServerAliveInterval=5",
		sshArgs{Option: sshOption{map[string][]string{"remotecommand": {"none"}, "serveraliveinterval": {"5"}}}})

	assertArgsEqual("--reconnect", sshArgs{Reconnect: true})
	assertArgsEqual("--dragfile", sshArgs{DragFile: true})
	assertArgsEqual("--tracelog", sshArgs{TraceLog: true})
	assertArgsEqual("--relay", sshArgs{Relay: true})
	assertArgsEqual("--client", sshArgs{Client: true})
	assertArgsEqual("--debug", sshArgs{Debug: true})
	assertArgsEqual("--zmodem", sshArgs{Zmodem: true})

	assertArgsEqual("--udp", sshArgs{Udp: true})
	assertArgsEqual("--tsshd-path /usr/bin/tsshd", sshArgs{TsshdPath: "/usr/bin/tsshd"})

	assertArgsEqual("--new-host", sshArgs{NewHost: true})
	assertArgsEqual("--enc-secret", sshArgs{EncSecret: true})
	assertArgsEqual("--install-trzsz", sshArgs{InstallTrzsz: true})
	assertArgsEqual("--install-tsshd", sshArgs{InstallTsshd: true})
	assertArgsEqual("--install-trzsz --install-path /bin", sshArgs{InstallTrzsz: true, InstallPath: "/bin"})
	assertArgsEqual("--install-trzsz --trzsz-version 1.1.6", sshArgs{InstallTrzsz: true, TrzszVersion: "1.1.6"})
	assertArgsEqual("--install-trzsz --trzsz-bin-path a.tgz", sshArgs{InstallTrzsz: true, TrzszBinPath: "a.tgz"})
	assertArgsEqual("--install-tsshd --install-path /bin", sshArgs{InstallTsshd: true, InstallPath: "/bin"})
	assertArgsEqual("--install-tsshd --tsshd-version 0.1.2", sshArgs{InstallTsshd: true, TsshdVersion: "0.1.2"})
	assertArgsEqual("--install-tsshd --tsshd-bin-path b.tgz", sshArgs{InstallTsshd: true, TsshdBinPath: "b.tgz"})

	assertArgsEqual("--upload-file /tmp/1", sshArgs{UploadFile: multiStr{[]string{"/tmp/1"}}})
	assertArgsEqual("--upload-file /tmp/1 --upload-file /tmp/2", sshArgs{UploadFile: multiStr{[]string{"/tmp/1", "/tmp/2"}}})
	assertArgsEqual("--download-path ~/Downloads", sshArgs{DownloadPath: "~/Downloads"})

	assertArgsEqual("dest", sshArgs{Destination: "dest"})
	assertArgsEqual("dest cmd", sshArgs{Destination: "dest", Command: "cmd"})
	assertArgsEqual("dest cmd arg1", sshArgs{Destination: "dest", Command: "cmd", Argument: []string{"arg1"}})
	assertArgsEqual("dest cmd arg1 arg2", sshArgs{Destination: "dest", Command: "cmd", Argument: []string{"arg1", "arg2"}})

	assertArgsEqual("-tp222 -oRemoteCommand=none -i~/.ssh/id_rsa -o ServerAliveCountMax=2 dest cmd arg1 arg2",
		sshArgs{ForceTTY: true, Port: 222, Identity: multiStr{values: []string{"~/.ssh/id_rsa"}},
			Option:      sshOption{map[string][]string{"remotecommand": {"none"}, "serveralivecountmax": {"2"}}},
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

func TestForwardArgs(t *testing.T) {
	assert := assert.New(t)
	assertDynamicForwardNil := func(argument string, address *string, port int) {
		t.Helper()
		var args sshArgs
		p, err := arg.NewParser(arg.Config{}, &args)
		assert.Nil(err)
		err = p.Parse([]string{"-D", argument})
		assert.Nil(err)
		assert.Equal(sshArgs{DynamicForward: bindArgs{[]*bindCfg{{argument, address, port}}}}, args)
	}
	assertDynamicForward := func(argument string, address string, port int) {
		t.Helper()
		assertDynamicForwardNil(argument, &address, port)
	}

	assertDynamicForwardNil("8000", nil, 8000)
	assertDynamicForward("127.0.0.1:8002", "127.0.0.1", 8002)
	assertDynamicForward("[fe80::6358:bbae:26f8:7859]:8003", "fe80::6358:bbae:26f8:7859", 8003)
	assertDynamicForward(":8004", "", 8004)
	assertDynamicForward("*:8005", "*", 8005)
	assertDynamicForward("::1/8006", "::1", 8006)

	assertLRFwd := func(ftype, argument string, expectedArg sshArgs) {
		t.Helper()
		var args sshArgs
		p, err := arg.NewParser(arg.Config{}, &args)
		assert.Nil(err)
		err = p.Parse([]string{ftype, argument})
		assert.Nil(err)
		assert.Equal(expectedArg, args)
	}
	assertLRForwardNil := func(argument string, bindAddr *string, bindPort int, destHost string, destPort int) {
		t.Helper()
		assertLRFwd("-L", argument, sshArgs{LocalForward: forwardArgs{[]*forwardCfg{
			{argument, bindAddr, bindPort, destHost, destPort}}}})
		assertLRFwd("-R", argument, sshArgs{RemoteForward: forwardArgs{[]*forwardCfg{
			{argument, bindAddr, bindPort, destHost, destPort}}}})
	}
	assertLRForward := func(argument string, bindAddr string, bindPort int, destHost string, destPort int) {
		t.Helper()
		assertLRForwardNil(argument, &bindAddr, bindPort, destHost, destPort)
	}
	assertLRForward("127.0.0.1:8001:[::1]:9001", "127.0.0.1", 8001, "::1", 9001)
	assertLRForward("::1/8002/localhost/9002", "::1", 8002, "localhost", 9002)
	assertLRForwardNil("8003:0.0.0.0:9003", nil, 8003, "0.0.0.0", 9003)
	assertLRForward("::/8004/::1/9004", "::", 8004, "::1", 9004)
	assertLRForward(":8001:[fe80::6358:bbae:26f8:7859]:9001", "", 8001, "fe80::6358:bbae:26f8:7859", 9001)
	assertLRForward("/8002/127.0.0.1/9002", "", 8002, "127.0.0.1", 9002)
	assertLRForwardNil("8003/::1/9003", nil, 8003, "::1", 9003)
	assertLRForward("*:8004:[fe80::6358:bbae:26f8:7859]:9004", "*", 8004, "fe80::6358:bbae:26f8:7859", 9004)
}

func TestSshOption(t *testing.T) {
	assert := assert.New(t)
	assertRemoteCommand := func(optionArg, optionValue string) {
		t.Helper()
		var args sshArgs
		p, err := arg.NewParser(arg.Config{}, &args)
		assert.Nil(err)
		err = p.Parse([]string{optionArg})
		assert.Nil(err)
		assert.Equal(sshArgs{Option: sshOption{map[string][]string{"remotecommand": {optionValue}}}}, args)
	}

	assertRemoteCommand("-oRemoteCommand echo abc", "echo abc")
	assertRemoteCommand("-o RemoteCommand echo abc", "echo abc")
	assertRemoteCommand("-o\tRemoteCommand\techo\tabc", "echo\tabc")

	assertRemoteCommand("-oRemoteCommand echo = abc", "echo = abc")
	assertRemoteCommand("-o RemoteCommand  echo  =  abc  ", "echo  =  abc")
	assertRemoteCommand("-o\tRemoteCommand \techo \t= \tabc \t", "echo \t= \tabc")

	assertRemoteCommand("-oRemoteCommand=echo abc", "echo abc")
	assertRemoteCommand("-o RemoteCommand = echo abc ", "echo abc")
	assertRemoteCommand("-o\tRemoteCommand\t=\techo abc ", "echo abc")

	assertRemoteCommand("-oRemoteCommand  =  echo  abc  ", "echo  abc")
	assertRemoteCommand("-o  RemoteCommand  =  echo  abc  ", "echo  abc")
	assertRemoteCommand("-o \tRemoteCommand \t= \techo \tabc\t ", "echo \tabc")

	assertRemoteCommand("-oRemoteCommand  =  echo = abc  ", "echo = abc")
	assertRemoteCommand("-o RemoteCommand  =  echo = abc  ", "echo = abc")
	assertRemoteCommand("-o \tRemoteCommand\t =\t echo\t =\t abc \t", "echo\t =\t abc")

	assertInvalidOption := func(optionArg string) {
		t.Helper()
		var args sshArgs
		p, err := arg.NewParser(arg.Config{}, &args)
		assert.Nil(err)
		err = p.Parse([]string{optionArg})
		assert.NotNil(err)
		if err != nil {
			assert.Contains(err.Error(), "invalid option")
		}
	}

	assertInvalidOption("-oRemoteCommand")
	assertInvalidOption("-oRemoteCommand ")
	assertInvalidOption("-oRemoteCommand \t ")
	assertInvalidOption("-oRemoteCommand=")
	assertInvalidOption("-oRemoteCommand = ")
	assertInvalidOption("-oRemoteCommand \t = \t ")

	assertInvalidOption("-o \t RemoteCommand")
	assertInvalidOption("-o \t RemoteCommand ")
	assertInvalidOption("-o \t RemoteCommand \t ")
	assertInvalidOption("-o \t RemoteCommand=")
	assertInvalidOption("-o \t RemoteCommand = ")
	assertInvalidOption("-o \t RemoteCommand \t = \t ")

	assertInvalidOption("-o=RemoteCommand")
	assertInvalidOption("-o =RemoteCommand")
	assertInvalidOption("-o= RemoteCommand")
	assertInvalidOption("-o = RemoteCommand")
	assertInvalidOption("-o\t=\tRemoteCommand")
}

func TestMultiOptions(t *testing.T) {
	assert := assert.New(t)
	assertSendEnvs := func(optionArgs []string, optionValues ...string) {
		t.Helper()
		var args sshArgs
		p, err := arg.NewParser(arg.Config{}, &args)
		assert.Nil(err)
		err = p.Parse(optionArgs)
		assert.Nil(err)
		assert.Equal(sshArgs{Option: sshOption{map[string][]string{"sendenv": optionValues}}}, args)
	}

	assertSendEnvs([]string{"-oSendEnv=ABC"}, "ABC")
	assertSendEnvs([]string{"-oSendEnv=ABC 123", "-o", "SendEnv XYZ"}, "ABC 123", "XYZ")
	assertSendEnvs([]string{"-o", "SendEnv ABC 123", "-oSendEnv = XYZ", "-oSendEnv m3"}, "ABC 123", "XYZ", "m3")
}

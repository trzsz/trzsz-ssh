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
	"fmt"
	"strings"
)

type sshOption struct {
	options map[string]string
}

type multiStr struct {
	values []string
}

type sshArgs struct {
	Ver         bool      `arg:"-V,--" help:"show program's version number and exit"`
	Destination string    `arg:"positional" help:"alias in ~/.ssh/config, or [user@]hostname[:port]"`
	Command     string    `arg:"positional" help:"command to execute instead of a login shell"`
	Argument    []string  `arg:"positional" help:"command arguments separated by spaces"`
	DisableTTY  bool      `arg:"-T,--" help:"disable pseudo-terminal allocation"`
	ForceTTY    bool      `arg:"-t,--" help:"force pseudo-terminal allocation"`
	Port        int       `arg:"-p,--" help:"port to connect to on the remote host"`
	Identity    multiStr  `arg:"-i,--" help:"identity (private key) for public key auth"`
	ProxyJump   string    `arg:"-J,--" help:"jump hosts separated by comma characters"`
	Option      sshOption `arg:"-o,--" help:"options in the format used in ~/.ssh/config\ne.g., tssh -o ProxyCommand=\"ssh proxy nc %h %p\""`
	DragFile    bool      `help:"enable drag files and directories to upload"`
	TraceLog    bool      `help:"enable trzsz detect trace logs for debugging"`
	Relay       bool      `help:"force trzsz run as a relay on the jump server"`
}

func (sshArgs) Description() string {
	return "Simple ssh client with trzsz ( trz / tsz ) support.\n"
}

func (sshArgs) Version() string {
	return fmt.Sprintf("trzsz ssh %s", kTsshVersion)
}

func (o *sshOption) UnmarshalText(b []byte) error {
	s := string(b)
	pos := strings.Index(s, "=")
	if pos < 1 {
		return fmt.Errorf("invalid option: %s", s)
	}
	if o.options == nil {
		o.options = make(map[string]string)
	}
	o.options[strings.ToLower(strings.TrimSpace(s[:pos]))] = strings.TrimSpace(s[pos+1:])
	return nil
}

func (o *sshOption) get(option string) string {
	if o.options == nil {
		return ""
	}
	return o.options[strings.ToLower(option)]
}

func (v *multiStr) UnmarshalText(b []byte) error {
	v.values = append(v.values, string(b))
	return nil
}

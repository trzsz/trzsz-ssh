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
	"os"
	"strings"

	"github.com/trzsz/go-arg"
	"golang.org/x/term"
)

const kTsshVersion = "0.1.1"

type sshOption struct {
	options map[string]string
}

type sshArgs struct {
	Ver         bool      `arg:"-V,--" help:"show program's version number and exit"`
	Terminal    bool      `arg:"-t,--" help:"force pseudo-terminal allocation (default)"`
	Destination string    `arg:"positional" help:"alias in ~/.ssh/config, or [user@]hostname[:port]"`
	Command     string    `arg:"positional" help:"command with arguments, instead of a login shell.\ne.g., tssh destination \"tmux -CC\""`
	Port        int       `arg:"-p,--" help:"port to connect to on the remote host"`
	Identity    string    `arg:"-i,--" help:"identity (private key) for public key auth"`
	ProxyJump   string    `arg:"-J,--" help:"jump hosts separated by comma characters"`
	Option      sshOption `arg:"-o,--" help:"options in the format used in ~/.ssh/config\ne.g., tssh -o ProxyCommand=\"ssh proxy nc %h %p\""`
	DragFile    bool      `help:"enable drag files and directories to upload"`
	TraceLog    bool      `help:"enable trzsz detect trace logs for debugging"`
}

func (sshArgs) Description() string {
	return "Simple ssh client with trzsz ( trz / tsz ) support.\n"
}

func (sshArgs) Version() string {
	return fmt.Sprintf("trzsz ssh %s", kTsshVersion)
}

func (o *sshOption) UnmarshalText(b []byte) error {
	s := string(b)
	if s == fmt.Sprintf("%s", sshOption{}) {
		return nil
	}
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

func TsshMain() int {
	var args sshArgs
	arg.MustParse(&args)

	// compatible with -V option
	if args.Ver {
		fmt.Println(args.Version())
		return 0
	}

	// print message after stdin reset
	var err error
	defer func() {
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
		}
	}()

	// setup terminal for Windows
	mode, err := setupTerminalMode()
	if err != nil {
		return -1
	}
	defer resetTerminalMode(mode)

	// make stdin to raw
	fd := int(os.Stdin.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		return -2
	}
	defer term.Restore(fd, state) // nolint:all

	// choose ssh alias
	if args.Destination == "" {
		var quit bool
		args.Destination, quit, err = chooseAlias()
		if quit {
			err = nil
			return 0
		}
		if err != nil {
			return -3
		}
	}

	// ssh login
	session, err := sshLogin(&args)
	if err != nil {
		return -4
	}

	// wait for exit
	if err := session.Wait(); err != nil {
		return -5
	}
	return 0
}

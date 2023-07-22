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
	"os/exec"
	"strings"
	"sync"

	"github.com/trzsz/go-arg"
	"github.com/trzsz/ssh_config"
	"golang.org/x/term"
)

const kTsshVersion = "0.1.8"

func background(dest string) (bool, error) {
	if v := os.Getenv("TRZSZ-SSH-BACKGROUND"); v == "TRUE" {
		return false, nil
	}
	env := append(os.Environ(), "TRZSZ-SSH-BACKGROUND=TRUE")
	args := os.Args
	if dest != "" {
		args = append(args, dest)
	}
	cmd := exec.Cmd{
		Path:   os.Args[0],
		Args:   args,
		Env:    env,
		Stderr: os.Stderr,
	}
	if err := cmd.Start(); err != nil {
		return true, err
	}
	return true, nil
}

var onExitFuncs []func()

func parseRemoteCommand(args *sshArgs) (string, error) {
	command := args.Option.get("RemoteCommand")
	if args.Command != "" && command != "" && strings.ToLower(command) != "none" {
		return "", fmt.Errorf("cannot execute command-line and remote command")
	}
	if args.Command != "" {
		if len(args.Argument) == 0 {
			return args.Command, nil
		}
		return fmt.Sprintf("%s %s", args.Command, strings.Join(args.Argument, " ")), nil
	}
	if strings.ToLower(command) == "none" {
		return "", nil
	} else if command != "" {
		return command, nil
	}
	return ssh_config.Get(args.Destination, "RemoteCommand"), nil
}

var isTerminal bool = term.IsTerminal(int(os.Stdin.Fd()))

func parseCmdAndTTY(args *sshArgs) (cmd string, tty bool, err error) {
	cmd, err = parseRemoteCommand(args)
	if err != nil {
		return
	}

	if args.DisableTTY && args.ForceTTY {
		err = fmt.Errorf("cannot specify -t with -T")
		return
	}
	if args.DisableTTY {
		tty = false
		return
	}
	if args.ForceTTY {
		tty = true
		return
	}

	requestTTY := strings.ToLower(ssh_config.Get(args.Destination, "RequestTTY"))
	switch requestTTY {
	case "", "auto":
		tty = isTerminal && (cmd == "")
	case "no":
		tty = false
	case "force":
		tty = true
	case "yes":
		tty = isTerminal
	default:
		err = fmt.Errorf("unknown RequestTTY option: %s", ssh_config.Get(args.Destination, "RequestTTY"))
	}
	return
}

func TsshMain() int {
	var args sshArgs
	parser := arg.MustParse(&args)

	// compatible with -V option
	if args.Ver {
		fmt.Println(args.Version())
		return 0
	}

	// debug log
	if args.Debug {
		enableDebugLogging = true
	}

	// cleanup on exit
	defer func() {
		for _, f := range onExitFuncs {
			f()
		}
	}()

	// print message after stdin reset
	var err error
	defer func() {
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\r\n", err)
		}
	}()

	// setup terminal
	var mode *terminalMode
	if isTerminal {
		mode, err = setupTerminalMode()
		if err != nil {
			return 1
		}
		defer resetTerminalMode(mode)
	}

	// choose ssh alias
	dest := ""
	if args.Destination == "" {
		if !isTerminal {
			parser.WriteHelp(os.Stderr)
			return 2
		}
		var quit bool
		dest, quit, err = chooseAlias()
		if quit {
			err = nil
			return 0
		}
		if err != nil {
			return 3
		}
		args.Destination = dest
	}

	// run as background
	if args.Background {
		var parent bool
		parent, err = background(dest)
		if err != nil {
			return 4
		}
		if parent {
			return 0
		}
	}

	// parse cmd and tty
	command, tty, err := parseCmdAndTTY(&args)
	if err != nil {
		return 5
	}

	// ssh login
	client, session, err := sshLogin(&args, tty)
	if err != nil {
		return 6
	}
	defer client.Close()
	if session != nil {
		defer session.Close()
	}

	// reset terminal if no login tty
	if mode != nil && (!tty || args.StdioForward != "" || args.NoCommand) {
		resetTerminalMode(mode)
	}

	// stdio forward
	if args.StdioForward != "" {
		var wg *sync.WaitGroup
		wg, err = stdioForward(client, args.StdioForward)
		if err != nil {
			return 7
		}
		wg.Wait()
		return 0
	}

	// ssh forward
	if err = sshForward(client, &args); err != nil {
		return 8
	}

	// no command
	if args.NoCommand {
		if client.Wait() != nil {
			return 9
		}
		return 0
	}

	// run command or start shell
	if command != "" {
		if err = session.Start(command); err != nil {
			err = fmt.Errorf("start command [%s] failed: %v", command, err)
			return 10
		}
	} else {
		if err = session.Shell(); err != nil {
			err = fmt.Errorf("start shell failed: %v", err)
			return 11
		}
	}

	// wait for exit
	if session.Wait() != nil {
		return 12
	}
	if args.Background && client.Wait() != nil {
		return 13
	}
	return 0
}

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
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/trzsz/go-arg"
)

const kTsshVersion = "0.1.21"

func background(args *sshArgs, dest string) (bool, error) {
	if v := os.Getenv("TRZSZ-SSH-BACKGROUND"); v == "TRUE" {
		return false, nil
	}

	monitor := false
	if v := os.Getenv("TRZSZ-SSH-BG-MONITOR"); v == "TRUE" {
		monitor = true
	}
	env := os.Environ()
	if args.Reconnect && !monitor {
		env = append(env, "TRZSZ-SSH-BG-MONITOR=TRUE")
	} else {
		env = append(env, "TRZSZ-SSH-BACKGROUND=TRUE")
	}

	newArgs := os.Args
	if args.Destination == "" {
		newArgs = append(newArgs, dest)
	} else if args.Destination != dest {
		idx := -1
		count := 0
		for i, arg := range newArgs {
			if arg == args.Destination {
				idx = i
				count++
			}
		}
		if count != 1 {
			return true, fmt.Errorf("don't know how to replace the destination: %s => %s", args.Destination, dest)
		}
		newArgs[idx] = dest
	}

	sleepTime := time.Duration(0)
	for {
		cmd := exec.Command(newArgs[0], newArgs[1:]...)
		cmd.Env = env
		cmd.Stderr = os.Stderr

		if err := cmd.Start(); err != nil {
			return true, fmt.Errorf("run in background failed: %v", err)
		}
		if !monitor {
			return true, nil
		}

		beginTime := time.Now()
		_ = cmd.Wait()
		if time.Since(beginTime) < 10*time.Second {
			if sleepTime < 10*time.Second {
				sleepTime += time.Second
			}
			time.Sleep(sleepTime)
		} else {
			sleepTime = 0
		}
	}
}

var onExitFuncs []func()

func cleanupOnExit() {
	for i := len(onExitFuncs) - 1; i >= 0; i-- {
		onExitFuncs[i]()
	}
}

var afterLoginFuncs []func()

func cleanupAfterLogin() {
	for i := len(afterLoginFuncs) - 1; i >= 0; i-- {
		afterLoginFuncs[i]()
	}
}

var isTerminal bool = isatty.IsTerminal(os.Stdin.Fd()) || isatty.IsCygwinTerminal(os.Stdin.Fd())

// TrzMain is the main function of tssh program.
func TsshMain(argv []string) int {
	// parse ssh args
	var args sshArgs
	parser, err := arg.NewParser(arg.Config{Out: os.Stderr, Exit: os.Exit}, &args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return -1
	}
	parser.MustParse(argv)

	// debug log
	if args.Debug {
		enableDebugLogging = true
	}

	// cleanup on exit
	defer cleanupOnExit()

	// print message after stdin reset
	defer func() {
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\r\n", err)
		}
	}()

	// init user config
	if err = initUserConfig(args.ConfigFile); err != nil {
		return 1
	}

	// setup virtual terminal on Windows
	if isTerminal {
		if err = setupVirtualTerminal(); err != nil {
			return 2
		}
	}

	// execute local tools if necessary
	if code, quit := execLocalTools(argv, &args); quit {
		return code
	}

	// choose ssh alias
	dest := ""
	quit := false
	if args.Destination == "" || args.Destination == "FAKE_DEST_IN_WARP" {
		if !isTerminal {
			parser.WriteHelp(os.Stderr)
			return 3
		}
		dest, quit, err = chooseAlias("")
	} else {
		dest, quit, err = predictDestination(args.Destination)
	}
	if quit {
		err = nil
		return 0
	}
	if err != nil {
		return 4
	}

	// run as background
	if args.Background {
		var parent bool
		parent, err = background(&args, dest)
		if err != nil {
			return 5
		}
		if parent {
			return 0
		}
	}
	args.Destination = dest
	args.originalDest = dest

	// start ssh program
	if err = sshStart(&args); err != nil {
		return 6
	}
	return 0
}

func sshStart(args *sshArgs) error {
	// ssh login
	ss, err := sshLogin(args)
	if err != nil {
		return err
	}
	defer ss.Close()

	// stdio forward
	if args.StdioForward != "" {
		var wg *sync.WaitGroup
		wg, err = stdioForward(ss.client, args.StdioForward)
		if err != nil {
			return err
		}
		cleanupAfterLogin()
		wg.Wait()
		return nil
	}

	// not executing remote command
	if args.NoCommand {
		cleanupAfterLogin()
		_ = ss.client.Wait()
		return nil
	}

	// set terminal title
	if userConfig.setTerminalTitle != "" {
		switch strings.ToLower(userConfig.setTerminalTitle) {
		case "yes", "true":
			setTerminalTitle(args.Destination)
		}
	}

	// execute remote tools if necessary
	execRemoteTools(args, ss.client)

	// run command or start shell
	if ss.cmd != "" {
		if err := ss.session.Start(ss.cmd); err != nil {
			return fmt.Errorf("start command [%s] failed: %v", ss.cmd, err)
		}
	} else {
		if err := ss.session.Shell(); err != nil {
			return fmt.Errorf("start shell failed: %v", err)
		}
	}

	// execute expect interactions if necessary
	execExpectInteractions(args, ss)

	// make stdin raw
	if isTerminal && ss.tty {
		state, err := makeStdinRaw()
		if err != nil {
			return err
		}
		defer resetStdin(state)
	}

	// enable trzsz
	if err := enableTrzsz(args, ss); err != nil {
		return err
	}

	// cleanup and wait for exit
	cleanupAfterLogin()
	_ = ss.session.Wait()
	if args.Background {
		_ = ss.client.Wait()
	}
	return nil
}

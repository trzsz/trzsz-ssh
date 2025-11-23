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
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/trzsz/go-arg"
)

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
var onExitMutex sync.Mutex

func cleanupOnExit() {
	onExitMutex.Lock()
	defer onExitMutex.Unlock()
	var wg sync.WaitGroup
	for i := len(onExitFuncs) - 1; i >= 0; i-- {
		wg.Go(onExitFuncs[i])
	}
	wg.Wait()
	onExitFuncs = nil
}

func addOnExitFunc(f func()) {
	onExitMutex.Lock()
	defer onExitMutex.Unlock()
	onExitFuncs = append(onExitFuncs, f)
}

var onCloseFuncs []func()
var onCloseMutex sync.Mutex

func cleanupOnClose() {
	onCloseMutex.Lock()
	defer onCloseMutex.Unlock()
	var wg sync.WaitGroup
	for i := len(onCloseFuncs) - 1; i >= 0; i-- {
		wg.Go(onCloseFuncs[i])
	}
	wg.Wait()
	onCloseFuncs = nil
}

func addOnCloseFunc(f func()) {
	onCloseMutex.Lock()
	defer onCloseMutex.Unlock()
	onCloseFuncs = append(onCloseFuncs, f)
}

var afterLoginFuncs []func()
var afterLoginMutex sync.Mutex

func cleanupAfterLogin() {
	afterLoginMutex.Lock()
	defer afterLoginMutex.Unlock()
	var wg sync.WaitGroup
	for i := len(afterLoginFuncs) - 1; i >= 0; i-- {
		wg.Go(afterLoginFuncs[i])
	}
	wg.Wait()
	afterLoginFuncs = nil
}

func addAfterLoginFunc(f func()) {
	afterLoginMutex.Lock()
	defer afterLoginMutex.Unlock()
	afterLoginFuncs = append(afterLoginFuncs, f)
}

var isTerminal bool = isatty.IsTerminal(os.Stdin.Fd()) || isatty.IsCygwinTerminal(os.Stdin.Fd())

// TrzMain is the main function of tssh program.
func TsshMain(argv []string) int {
	// parse ssh args
	var args sshArgs
	parser, err := arg.NewParser(arg.Config{HideLongOptions: true, Out: os.Stderr, Exit: os.Exit}, &args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return kExitCodeArgsInvalid
	}
	parser.MustParse(argv)

	// debug log
	if args.Debug {
		enableDebugLogging = true
	}

	// print message after stdin reset
	defer func() {
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\r\n", err)
		}
	}()

	// cleanup on exit
	defer cleanupOnExit()

	// init user config
	if err = initUserConfig(args.ConfigFile); err != nil {
		return kExitCodeUserConfig
	}

	// setup virtual terminal on Windows
	if isTerminal {
		if err = setupVirtualTerminal(); err != nil {
			return kExitCodeSetupWinVT
		}
	}

	// execute local tools if necessary
	if code, quit := execLocalTools(&args); quit {
		return code
	}

	// choose ssh alias
	dest := ""
	quit := false
	if args.Destination == "" || args.Destination == "FAKE_DEST_IN_WARP" {
		if !isTerminal {
			parser.WriteHelp(os.Stderr)
			return kExitCodeNoDestHost
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
		return kExitCodeNoDestHost
	}

	// run as background
	if args.Background {
		var parent bool
		parent, err = background(&args, dest)
		if err != nil {
			return kExitCodeBackground
		}
		if parent {
			return 0
		}
	}
	args.Destination = dest
	args.originalDest = dest

	if args.Dns != "" {
		setDNS(args.Dns)
	}

	// start ssh program
	var code int
	code, err = sshStart(&args)
	return code
}

func sshStart(args *sshArgs) (int, error) {
	// ssh login
	ss, err := sshLogin(args)
	if err != nil {
		return kExitCodeLoginFailed, err
	}
	defer ss.Close()

	// cleanup on close
	defer cleanupOnClose()

	// stdio forward
	if args.StdioForward != "" {
		cleanupAfterLogin()
		if err = stdioForward(args, ss.client, args.StdioForward); err != nil {
			return kExitCodeIoFwFailed, err
		}
		return 0, nil
	}

	// request subsystem
	if args.Subsystem {
		cleanupAfterLogin()
		if err = subsystemForward(ss); err != nil {
			return kExitCodeSubFwFailed, err
		}
		return 0, nil
	}

	// not executing remote command
	if args.NoCommand {
		cleanupAfterLogin()
		_ = ss.client.Wait()
		return 0, nil
	}

	// set terminal title
	if userConfig.setTerminalTitle != "" {
		switch strings.ToLower(userConfig.setTerminalTitle) {
		case "yes", "true":
			setTerminalTitle(args.Destination)
		}
	}

	// execute remote tools if necessary
	if code, quit := execRemoteTools(args, ss); quit {
		return code, nil
	}

	// enable waypipe
	if err := enableWaypipe(args, ss); err != nil {
		warning("waypipe may not be working properly: %v", err)
	}

	// run command or start shell
	if ss.cmd != "" {
		if err := ss.session.Start(ss.cmd); err != nil {
			return kExitCodeStartFailed, fmt.Errorf("start command [%s] failed: %v", ss.cmd, err)
		}
	} else {
		if err := ss.session.Shell(); err != nil {
			return kExitCodeShellFailed, fmt.Errorf("start shell failed: %v", err)
		}
	}

	// execute expect interactions if necessary
	execExpectInteractions(args, ss)

	// make stdin raw
	if isTerminal && ss.tty {
		state, err := makeStdinRaw()
		if err != nil {
			return kExitCodeStdinFailed, err
		}
		addOnExitFunc(func() { resetStdin(state) })
		defer resetStdin(state)
	}

	// enable trzsz
	if err := enableTrzsz(args, ss); err != nil {
		return kExitCodeTrzszFailed, err
	}

	// cleanup and wait for exit
	cleanupAfterLogin()
	_ = ss.session.Wait()
	debug("session wait completed")
	if args.Background {
		_ = ss.client.Wait()
	}

	// wait for the output
	outputWaitGroup.Wait()
	debug("output wait completed")
	return ss.session.GetExitCode(), nil
}

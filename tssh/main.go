/*
MIT License

Copyright (c) 2023-2026 The Trzsz SSH Authors.

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
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/trzsz/go-arg"
	"golang.org/x/crypto/ssh"
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
	for i := len(onExitFuncs) - 1; i >= 0; i-- { // close proxy clients in order
		onExitFuncs[i]()
	}
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
	for i := len(onCloseFuncs) - 1; i >= 0; i-- {
		onCloseFuncs[i]()
	}
	onCloseFuncs = nil
}

func addOnCloseFunc(f func()) {
	onCloseMutex.Lock()
	defer onCloseMutex.Unlock()
	onCloseFuncs = append(onCloseFuncs, f)
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

	// init iterm2 session if necessary
	initIterm2Session()

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
	sshConn, err := sshConnect(args)
	if err != nil {
		return kExitCodeLoginFailed, err
	}
	defer func() {
		cleanupOnClose()
		sshConn.Close()
	}()

	// execute local command if necessary
	execLocalCommand(sshConn.param)

	// handle signals
	handleExitSignals(sshConn)

	// stdio forward
	if args.StdioForward != "" {
		if err = stdioForward(args, sshConn.client, args.StdioForward); err != nil {
			return kExitCodeIoFwFailed, err
		}
		return 0, nil
	}

	// request subsystem
	if args.Subsystem {
		if err = subsystemForward(sshConn.client, sshConn.cmd); err != nil {
			return kExitCodeSubFwFailed, err
		}
		return 0, nil
	}

	// ssh port forwarding
	if !sshConn.param.control {
		sshPortForward(sshConn)
	}

	// not executing remote command
	if args.NoCommand {
		_ = sshConn.client.Wait()
		return 0, nil
	}

	// open ssh session
	if err = openSession(sshConn); err != nil {
		return kExitCodeOpenSession, err
	}

	// ssh agent forward
	if !sshConn.param.control {
		sshAgentForward(sshConn)
	}

	// x11 forward
	sshX11Forward(sshConn)

	// set terminal title
	if userConfig.setTerminalTitle != "" {
		switch strings.ToLower(userConfig.setTerminalTitle) {
		case "yes", "true":
			setTerminalTitle(args.Destination)
		}
	}

	// execute remote tools if necessary
	if code, quit := execRemoteTools(sshConn); quit {
		return code, nil
	}

	// enable waypipe
	if err := enableWaypipe(sshConn); err != nil {
		warning("waypipe may not be working properly: %v", err)
	}

	// run command or start shell
	if sshConn.cmd != "" {
		if err := sshConn.session.Start(sshConn.cmd); err != nil {
			return kExitCodeStartFailed, fmt.Errorf("start command [%s] failed: %v", sshConn.cmd, err)
		}
	} else {
		if err := sshConn.session.Shell(); err != nil {
			return kExitCodeShellFailed, fmt.Errorf("start shell failed: %v", err)
		}
	}

	// execute expect interactions if necessary
	execExpectInteractions(sshConn)

	// make stdin raw
	if isTerminal && sshConn.tty {
		state, err := makeStdinRaw()
		if err != nil {
			return kExitCodeStdinFailed, err
		}
		addOnExitFunc(func() { resetStdin(state) })
		defer resetStdin(state)
	}

	// setup trzsz filter if necessary
	if err := setupTrzszFilter(sshConn); err != nil {
		return kExitCodeTrzszFailed, err
	}

	// setup udp notification if necessary
	setupUdpNotification(sshConn)

	// forward standard input output
	forwardStdio(sshConn)

	// cleanup and wait for exit
	code := sshConn.waitUntilExit()
	if args.Background {
		_ = sshConn.client.Wait()
	}

	// wait for the output
	outputWaitGroup.Wait()
	debug("ssh session output wait completed")
	return code, nil
}

func execLocalCommand(param *sshParam) {
	if strings.ToLower(getOptionConfig(param.args, "PermitLocalCommand")) != "yes" {
		return
	}
	localCmd := getOptionConfig(param.args, "LocalCommand")
	if localCmd == "" {
		return
	}
	expandedCmd, err := expandTokens(localCmd, param, "%CdfHhIijKkLlnprTtu")
	if err != nil {
		warning("expand LocalCommand [%s] failed: %v", localCmd, err)
		return
	}
	resolvedCmd := resolveHomeDir(expandedCmd)
	debug("exec local command: %s", resolvedCmd)

	argv, err := splitCommandLine(resolvedCmd)
	if err != nil || len(argv) == 0 {
		warning("split local command [%s] failed: %v", resolvedCmd, err)
		return
	}
	if enableDebugLogging {
		for i, arg := range argv {
			debug("local command argv[%d] = %s", i, arg)
		}
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		warning("exec local command [%s] failed: %v", resolvedCmd, err)
	}
}

func openSession(sshConn *sshConnection) (err error) {
	// new session
	sshConn.session, err = sshConn.client.NewSession()
	if err != nil {
		return fmt.Errorf("new session for [%s] failed: %v", sshConn.param.args.Destination, err)
	}

	// session input and output
	sshConn.serverIn, err = sshConn.session.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe for [%s] failed: %v", sshConn.param.args.Destination, err)
	}
	sshConn.serverOut, err = sshConn.session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe for [%s] failed: %v", sshConn.param.args.Destination, err)
	}
	sshConn.serverErr, err = sshConn.session.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe for [%s] failed: %v", sshConn.param.args.Destination, err)
	}

	// send and set env
	term, err := sendAndSetEnv(sshConn)
	if err != nil {
		return err
	}

	// pty is not needed if not tty in terminal
	if !isTerminal || !sshConn.tty {
		return nil
	}

	// request pty
	width, height, err := getTerminalSize()
	if err != nil {
		return fmt.Errorf("get terminal size for [%s] failed: %v", sshConn.param.args.Destination, err)
	}
	if term == "" {
		term = os.Getenv("TERM")
		if term == "" {
			term = "xterm-256color"
		}
	}
	if err := sshConn.session.RequestPty(term, height, width, ssh.TerminalModes{}); err != nil {
		return fmt.Errorf("request pty for [%s] failed: %v", sshConn.param.args.Destination, err)
	}

	return nil
}

func handleExitSignals(sshConn *sshConnection) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan,
		syscall.SIGTERM, // Default signal for the kill command
		syscall.SIGHUP,  // Terminal closed (System reboot/shutdown)
		os.Interrupt,    // Ctrl+C signal
	)
	go func() {
		for sig := range sigChan {
			if enableDebugLogging && debugCleanuped.Load() {
				_, _ = os.Stderr.WriteString("\r\n")
				os.Exit(kExitCodeSignalKill)
			}
			if isRunningOnOldWindows.Load() && sig.String() == "interrupt" {
				continue
			}
			sshConn.forceExit(kExitCodeSignalKill, fmt.Sprintf("Exit due to signal [%v] from the operating system", sig))
			break
		}
	}()
}

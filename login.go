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
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/chzyer/readline"
	"github.com/kevinburke/ssh_config"
	"github.com/trzsz/trzsz-go/trzsz"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
)

var userHomeDir string

type loginParam struct {
	host    string
	port    string
	user    string
	addr    string
	proxy   []string
	command string
}

var portRegexp = regexp.MustCompile(`:(\d+)$`)

func getLoginParamFromArgs(args *sshArgs) (*loginParam, error) {
	param := &loginParam{}

	// login user
	idx := strings.Index(args.Destination, "@")
	if idx > 0 {
		param.host = args.Destination[idx+1:]
		param.user = args.Destination[:idx]
	} else {
		param.host = args.Destination
		currentUser, err := user.Current()
		if err != nil {
			return nil, fmt.Errorf("get current user failed: %v", err)
		}
		param.user = currentUser.Username
	}

	// login addr
	if args.Port > 0 {
		param.port = strconv.Itoa(args.Port)
	} else {
		match := portRegexp.FindSubmatch([]byte(param.host))
		if len(match) == 2 {
			param.host = param.host[:strings.LastIndex(param.host, ":")]
			param.port = string(match[1])
		} else {
			param.port = "22"
		}
	}
	param.addr = fmt.Sprintf("%s:%s", param.host, param.port)

	// login proxy
	command := args.Option.get("ProxyCommand")
	if command != "" && args.ProxyJump != "" {
		return nil, fmt.Errorf("Cannot specify -J with ProxyCommand")
	}
	if command != "" {
		param.command = command
	} else if args.ProxyJump != "" {
		param.proxy = strings.Split(args.ProxyJump, ",")
	}

	return param, nil
}

func getLoginParam(args *sshArgs) (*loginParam, error) {
	host := ssh_config.Get(args.Destination, "HostName")
	if host == "" { // from args
		return getLoginParamFromArgs(args)
	}

	// ssh alias
	param := &loginParam{host: host}

	// login user
	param.user = ssh_config.Get(args.Destination, "User")
	if param.user == "" {
		currentUser, err := user.Current()
		if err != nil {
			return nil, fmt.Errorf("get current user failed: %v", err)
		}
		param.user = currentUser.Username
	}

	// login addr
	if args.Port > 0 {
		param.port = strconv.Itoa(args.Port)
	} else {
		param.port = ssh_config.Get(args.Destination, "Port")
	}
	param.addr = fmt.Sprintf("%s:%s", param.host, param.port)

	// login proxy
	command := args.Option.get("ProxyCommand")
	if command != "" && args.ProxyJump != "" {
		return nil, fmt.Errorf("Cannot specify -J with ProxyCommand")
	}
	if command != "" {
		param.command = command
	} else if args.ProxyJump != "" {
		param.proxy = strings.Split(args.ProxyJump, ",")
	} else {
		proxy := ssh_config.Get(args.Destination, "ProxyJump")
		if proxy != "" {
			param.proxy = strings.Split(proxy, ",")
		} else {
			command := ssh_config.Get(args.Destination, "ProxyCommand")
			if command != "" {
				param.command = command
			}
		}
	}

	return param, nil
}

func createKnownHosts(path string) error {
	file, err := os.OpenFile(path, os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("create [%s] failed: %v", path, err)
	}
	defer file.Close()
	return nil
}

func addHostKey(path, host string, remote net.Addr, key ssh.PublicKey) error {
	fingerprint := ssh.FingerprintSHA256(key)
	fmt.Printf("The authenticity of host '%s' can't be established.\r\n"+
		"%s key fingerprint is %s.\r\n", host, key.Type(), fingerprint)

	defer fmt.Print("\r")
	rl, err := readline.New("Are you sure you want to continue connecting (yes/no/[fingerprint])? ")
	if err != nil {
		return err
	}
	for {
		input, err := rl.Readline()
		if err != nil {
			return err
		}
		input = strings.TrimSpace(input)
		if input == fingerprint {
			break
		}
		input = strings.ToLower(input)
		if input == "yes" {
			break
		} else if input == "no" {
			return fmt.Errorf("host key not trusted")
		} else {
			rl.SetPrompt("Please type 'yes', 'no' or the fingerprint: ")
		}
	}

	fmt.Printf("\r\033[0;33mWarning: Permanently added '%s' (%s) to the list of known hosts.\033[0m\r\n", host, key.Type())
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	knownHost := knownhosts.Normalize(host)
	_, err = file.WriteString(knownhosts.Line([]string{knownHost}, key) + "\n")
	return err
}

var getHostKeyCallback = func() func() (ssh.HostKeyCallback, error) {
	var err error
	var once sync.Once
	var hkcb ssh.HostKeyCallback
	return func() (ssh.HostKeyCallback, error) {
		once.Do(func() {
			path := filepath.Join(userHomeDir, ".ssh", "known_hosts")
			if err = createKnownHosts(path); err != nil {
				return
			}
			var cb ssh.HostKeyCallback
			cb, err = knownhosts.New(path)
			if err != nil {
				err = fmt.Errorf("new knownhosts [%s] failed: %v", path, err)
				return
			}
			hkcb = func(host string, remote net.Addr, key ssh.PublicKey) error {
				var keyErr *knownhosts.KeyError
				err := cb(host, remote, key)
				if errors.As(err, &keyErr) && len(keyErr.Want) > 0 {
					fmt.Printf("\033[0;31m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n"+
						"@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\r\n"+
						"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n"+
						"IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\r\n"+
						"Someone could be eavesdropping on you right now (man-in-the-middle attack)!\033[0m\r\n"+
						"It is also possible that a host key has just been changed.\r\n"+
						"The fingerprint for the %s key sent by the remote host is\r\n"+
						"%s\r\n"+
						"Please contact your system administrator.\r\n"+
						"Add correct host key in %s to get rid of this message.\r\n",
						key.Type(), ssh.FingerprintSHA256(key), path)
					return keyErr
				} else if errors.As(err, &keyErr) && len(keyErr.Want) == 0 {
					return addHostKey(path, host, remote, key)
				}
				return err
			}
		})
		return hkcb, err
	}
}()

func getSigner(path string) (ssh.Signer, error) {
	privateKey, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key [%s] failed: %v", path, err)
	}
	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("parse private key [%s] failed: %v", path, err)
	}
	return signer, nil
}

func getPasswordAuthMethod(host, user string) ssh.AuthMethod {
	return ssh.PasswordCallback(func() (secret string, err error) {
		fmt.Printf("%s@%s's password: ", user, host)
		defer fmt.Print("\r\n")
		errch := make(chan error, 1)
		defer close(errch)

		sigch := make(chan os.Signal, 1)
		signal.Notify(sigch, os.Interrupt)
		go func() {
			for range sigch {
				errch <- fmt.Errorf("interrupt")
			}
		}()
		defer func() { signal.Stop(sigch); close(sigch) }()

		go func() {
			pw, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				errch <- err
				return
			}
			secret = string(pw)
			errch <- nil
		}()
		err = <-errch
		return
	})
}

func getKeyboardInteractiveAuthMethod(host, user string) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		defer fmt.Print("\r\n")
		var answers []string
		errch := make(chan error, 1)
		defer close(errch)

		sigch := make(chan os.Signal, 1)
		signal.Notify(sigch, os.Interrupt)
		go func() {
			for range sigch {
				errch <- fmt.Errorf("interrupt")
			}
		}()
		defer func() { signal.Stop(sigch); close(sigch) }()

		go func() {
			for i, question := range questions {
				if i > 0 {
					fmt.Print("\r\n")
				}
				fmt.Printf("(%s@%s) %s", user, host, question)
				pw, err := term.ReadPassword(int(syscall.Stdin))
				if err != nil {
					errch <- err
					return
				}
				answers = append(answers, string(pw))
			}
			errch <- nil
		}()
		return answers, <-errch
	})
}

var getDefaultSigners = func() func() ([]ssh.Signer, error) {
	var err error
	var once sync.Once
	var signers []ssh.Signer
	return func() ([]ssh.Signer, error) {
		once.Do(func() {
			for _, name := range []string{ssh_config.Default("IdentityFile"), "id_rsa", "id_ecdsa",
				"id_ecdsa_sk", "id_ed25519", "id_ed25519_sk", "id_dsa"} {
				path := filepath.Join(userHomeDir, ".ssh", name)
				if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
					continue
				}
				var signer ssh.Signer
				signer, err = getSigner(path)
				if err != nil {
					return
				}
				signers = append(signers, signer)
			}
		})
		return signers, err
	}
}()

func getAuthMethods(args *sshArgs, host, user string) ([]ssh.AuthMethod, error) {
	var signers []ssh.Signer
	if args.Identity != "" {
		signer, err := getSigner(args.Identity)
		if err != nil {
			return nil, err
		}
		signers = []ssh.Signer{signer}
	} else {
		identity := ssh_config.Get(args.Destination, "IdentityFile")
		if identity != ssh_config.Default("IdentityFile") {
			signer, err := getSigner(identity)
			if err != nil {
				return nil, err
			}
			signers = []ssh.Signer{signer}
		} else {
			var err error
			signers, err = getDefaultSigners()
			if err != nil {
				return nil, err
			}
		}
	}

	var authMethods []ssh.AuthMethod
	if len(signers) > 0 {
		authMethods = append(authMethods, ssh.PublicKeys(signers...))
	}
	authMethods = append(authMethods, getPasswordAuthMethod(host, user), getKeyboardInteractiveAuthMethod(host, user))
	return authMethods, nil
}

type cmdAddr struct {
	addr string
}

func (*cmdAddr) Network() string {
	return "cmd"
}

func (a *cmdAddr) String() string {
	return a.addr
}

type cmdPipe struct {
	stdin  io.WriteCloser
	stdout io.ReadCloser
	addr   string
}

func (p *cmdPipe) LocalAddr() net.Addr {
	return &cmdAddr{"127.0.0.1:22"}
}

func (p *cmdPipe) RemoteAddr() net.Addr {
	return &cmdAddr{p.addr}
}

func (p *cmdPipe) Read(b []byte) (int, error) {
	return p.stdout.Read(b)
}

func (p *cmdPipe) Write(b []byte) (int, error) {
	return p.stdin.Write(b)
}

func (p *cmdPipe) SetDeadline(t time.Time) error {
	return nil
}

func (p *cmdPipe) SetReadDeadline(t time.Time) error {
	return nil
}

func (p *cmdPipe) SetWriteDeadline(t time.Time) error {
	return nil
}

func (p *cmdPipe) Close() error {
	err := p.stdin.Close()
	err2 := p.stdout.Close()
	if err != nil {
		return err
	}
	return err2
}

func execProxyCommand(param *loginParam) (net.Conn, string, error) {
	command := param.command
	command = strings.ReplaceAll(command, "%h", param.host)
	command = strings.ReplaceAll(command, "%p", param.port)
	command = strings.ReplaceAll(command, "%r", param.user)

	var cmd *exec.Cmd
	if !strings.ContainsAny(command, "'\"\\") {
		tokens := strings.Fields(command)
		cmd = exec.Command(tokens[0], tokens[1:]...)
	} else if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", command)
	} else {
		cmd = exec.Command("sh", "-c", command)
	}

	cmdIn, err := cmd.StdinPipe()
	if err != nil {
		return nil, command, err
	}
	cmdOut, err := cmd.StdoutPipe()
	if err != nil {
		return nil, command, err
	}
	if err := cmd.Start(); err != nil {
		return nil, command, err
	}

	return &cmdPipe{stdin: cmdIn, stdout: cmdOut, addr: param.addr}, command, nil
}

func sshConnect(args *sshArgs, client *ssh.Client, proxy string) (*ssh.Client, error) {
	param, err := getLoginParam(args)
	if err != nil {
		return nil, err
	}
	authMethods, err := getAuthMethods(args, param.host, param.user)
	if err != nil {
		return nil, err
	}
	hostkeyCallback, err := getHostKeyCallback()
	if err != nil {
		return nil, err
	}
	config := &ssh.ClientConfig{
		User:            param.user,
		Auth:            authMethods,
		Timeout:         3 * time.Second,
		HostKeyCallback: hostkeyCallback,
	}

	proxyConnect := func(client *ssh.Client, proxy string) (*ssh.Client, error) {
		conn, err := client.Dial("tcp", param.addr)
		if err != nil {
			return nil, fmt.Errorf("proxy [%s] dial tcp [%s] failed: %v", proxy, param.addr, err)
		}
		ncc, chans, reqs, err := ssh.NewClientConn(conn, param.addr, config)
		if err != nil {
			return nil, fmt.Errorf("proxy [%s] new conn [%s] failed: %v", proxy, param.addr, err)
		}
		return ssh.NewClient(ncc, chans, reqs), nil
	}

	// has parent client
	if client != nil {
		return proxyConnect(client, proxy)
	}

	// proxy command
	if param.command != "" {
		conn, cmd, err := execProxyCommand(param)
		if err != nil {
			return nil, fmt.Errorf("exec proxy command [%s] failed: %v", cmd, err)
		}
		ncc, chans, reqs, err := ssh.NewClientConn(conn, param.addr, config)
		if err != nil {
			return nil, fmt.Errorf("proxy command [%s] new conn [%s] failed: %v", cmd, param.addr, err)
		}
		return ssh.NewClient(ncc, chans, reqs), nil
	}

	// no proxy
	if len(param.proxy) == 0 {
		client, err := ssh.Dial("tcp", param.addr, config)
		if err != nil {
			return nil, fmt.Errorf("ssh dial tcp [%s] failed: %v", param.addr, err)
		}
		return client, nil
	}

	// has proxies
	var proxyClient *ssh.Client
	for _, proxy = range param.proxy {
		proxyClient, err = sshConnect(&sshArgs{Destination: proxy}, proxyClient, proxy)
		if err != nil {
			return nil, err
		}
	}
	return proxyConnect(proxyClient, proxy)
}

func keepAlive(client *ssh.Client, args *sshArgs) {
	getOptionValue := func(option string) int {
		value, err := strconv.Atoi(args.Option.get(option))
		if err == nil && value > 0 {
			return value
		}
		value, err = strconv.Atoi(ssh_config.Get(args.Destination, option))
		if err == nil && value > 0 {
			return value
		}
		return 0
	}

	serverAliveInterval := getOptionValue("ServerAliveInterval")
	if serverAliveInterval <= 0 {
		serverAliveInterval = 10
	}
	serverAliveCountMax := getOptionValue("ServerAliveCountMax")
	if serverAliveCountMax <= 0 {
		serverAliveCountMax = 3
	}

	t := time.NewTicker(time.Duration(serverAliveInterval) * time.Second)
	defer t.Stop()
	n := 0
	for range t.C {
		if _, _, err := client.SendRequest("keepalive@trzsz-ssh", true, nil); err != nil {
			n++
			if n >= serverAliveCountMax {
				client.Close()
				return
			}
		} else {
			n = 0
		}
	}
}

func getRemoteCommand(args *sshArgs) string {
	if args.Command != "" {
		return args.Command
	}
	return ssh_config.Get(args.Destination, "RemoteCommand")
}

func sshLogin(args *sshArgs) (*ssh.Session, error) {
	// init user home
	var err error
	userHomeDir, err = os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("user home dir failed: %v", err)
	}

	// ssh login
	client, err := sshConnect(args, nil, "")
	if err != nil {
		return nil, err
	}
	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("ssh new session failed: %v", err)
	}

	// request pty session
	width, height, err := getTerminalSize()
	if err != nil {
		return nil, fmt.Errorf("get terminal size failed: %v", err)
	}
	if err := session.RequestPty("xterm-256color", height, width, ssh.TerminalModes{}); err != nil {
		return nil, fmt.Errorf("request pty failed: %v", err)
	}

	// session input and output
	serverIn, err := session.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe failed: %v", err)
	}
	serverOut, err := session.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe failed: %v", err)
	}

	// create a TrzszFilter to support trzsz ( trz / tsz )
	//
	//   os.Stdin  ┌────────┐   os.Stdin   ┌─────────────┐   ServerIn   ┌────────┐
	// ───────────►│        ├─────────────►│             ├─────────────►│        │
	//             │        │              │ TrzszFilter │              │        │
	// ◄───────────│ Client │◄─────────────┤             │◄─────────────┤ Server │
	//   os.Stdout │        │   os.Stdout  └─────────────┘   ServerOut  │        │
	// ◄───────────│        │◄──────────────────────────────────────────┤        │
	//   os.Stderr └────────┘                  stderr                   └────────┘
	trzszFilter := trzsz.NewTrzszFilter(os.Stdin, os.Stdout, serverIn, serverOut, trzsz.TrzszOptions{
		TerminalColumns: int32(width),
		DetectDragFile:  args.DragFile,
		DetectTraceLog:  args.TraceLog,
	})
	session.Stderr = os.Stderr

	// reset terminal size on resize
	onTerminalResize(func(width, height int) {
		trzszFilter.SetTerminalColumns(int32(width))
		_ = session.WindowChange(height, width)
	})

	// keep alive
	go keepAlive(client, args)

	// start shell
	command := getRemoteCommand(args)
	if command != "" {
		if err := session.Start(command); err != nil {
			return nil, fmt.Errorf("start command [%s] failed: %v", command, err)
		}
	} else {
		if err := session.Shell(); err != nil {
			return nil, fmt.Errorf("start shell failed: %v", err)
		}
	}

	return session, nil
}

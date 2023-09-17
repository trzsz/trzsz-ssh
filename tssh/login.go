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
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/skeema/knownhosts"
	"github.com/trzsz/trzsz-go/trzsz"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)

var enableDebugLogging bool

func debug(format string, a ...any) {
	if !enableDebugLogging {
		return
	}
	fmt.Fprintf(os.Stderr, fmt.Sprintf("\033[0;36mdebug:\033[0m %s\r\n", format), a...)
}

func warning(format string, a ...any) {
	fmt.Fprintf(os.Stderr, fmt.Sprintf("\033[0;33mWarning: %s\033[0m\r\n", format), a...)
}

type loginParam struct {
	host    string
	port    string
	user    string
	addr    string
	proxy   []string
	command string
}

func joinHostPort(host, port string) string {
	if !strings.HasPrefix(host, "[") && strings.ContainsRune(host, ':') {
		return fmt.Sprintf("[%s]:%s", host, port)
	}
	return fmt.Sprintf("%s:%s", host, port)
}

func parseDestination(dest string) (user, host, port string) {
	// user
	idx := strings.Index(dest, "@")
	if idx >= 0 {
		user = dest[:idx]
		dest = dest[idx+1:]
	}

	// port
	idx = strings.Index(dest, "]:")
	if idx > 0 && dest[0] == '[' { // ipv6 port
		port = dest[idx+2:]
		dest = dest[1:idx]
	} else {
		tokens := strings.Split(dest, ":")
		if len(tokens) == 2 { // ipv4 port
			port = tokens[1]
			dest = tokens[0]
		}
	}

	host = dest
	return
}

func getLoginParam(args *sshArgs) (*loginParam, error) {
	param := &loginParam{}

	// login dest
	destUser, destHost, destPort := parseDestination(args.Destination)
	args.Destination = destHost

	// login host
	hostName := getConfig(destHost, "HostName")
	if hostName != "" {
		param.host = hostName
	} else {
		param.host = destHost
	}

	// login user
	if args.LoginName != "" {
		param.user = args.LoginName
	} else if destUser != "" {
		param.user = destUser
	} else {
		userName := getConfig(destHost, "User")
		if userName != "" {
			param.user = userName
		} else {
			currentUser, err := user.Current()
			if err != nil {
				return nil, fmt.Errorf("get current user failed: %v", err)
			}
			userName = currentUser.Username
			if idx := strings.LastIndexByte(userName, '\\'); idx >= 0 {
				userName = userName[idx+1:]
			}
			param.user = userName
		}
	}

	// login port
	if args.Port > 0 {
		param.port = strconv.Itoa(args.Port)
	} else if destPort != "" {
		param.port = destPort
	} else {
		port := getConfig(destHost, "Port")
		if port != "" {
			param.port = port
		} else {
			param.port = "22"
		}
	}

	// login addr
	param.addr = joinHostPort(param.host, param.port)

	// login proxy
	command := args.Option.get("ProxyCommand")
	if command != "" && args.ProxyJump != "" {
		return nil, fmt.Errorf("cannot specify -J with ProxyCommand")
	}
	if command != "" {
		param.command = command
	} else if args.ProxyJump != "" {
		param.proxy = strings.Split(args.ProxyJump, ",")
	} else {
		proxy := getConfig(destHost, "ProxyJump")
		if proxy != "" {
			param.proxy = strings.Split(proxy, ",")
		} else {
			command := getConfig(destHost, "ProxyCommand")
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
	fmt.Fprintf(os.Stderr, "The authenticity of host '%s' can't be established.\r\n"+
		"%s key fingerprint is %s.\r\n", host, key.Type(), fingerprint)

	stdin, closer, err := getKeyboardInput()
	if err != nil {
		return err
	}
	defer closer()

	reader := bufio.NewReader(stdin)
	fmt.Fprintf(os.Stderr, "Are you sure you want to continue connecting (yes/no/[fingerprint])? ")
	for {
		input, err := reader.ReadString('\n')
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
		}
		fmt.Fprintf(os.Stderr, "Please type 'yes', 'no' or the fingerprint: ")
	}

	writeKnownHost := func() error {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return err
		}
		defer file.Close()
		return knownhosts.WriteKnownHost(file, host, remote, key)
	}

	if err = writeKnownHost(); err != nil {
		warning("Failed to add the host to the list of known hosts (%s): %v", path, err)
		return nil
	}

	warning("Permanently added '%s' (%s) to the list of known hosts.", host, key.Type())
	return nil
}

var getHostKeyCallback = func() func() (ssh.HostKeyCallback, knownhosts.HostKeyCallback, error) {
	var err error
	var once sync.Once
	var cb ssh.HostKeyCallback
	var kh knownhosts.HostKeyCallback
	return func() (ssh.HostKeyCallback, knownhosts.HostKeyCallback, error) {
		once.Do(func() {
			path := filepath.Join(userHomeDir, ".ssh", "known_hosts")
			if err = createKnownHosts(path); err != nil {
				return
			}
			kh, err = knownhosts.New(path)
			if err != nil {
				err = fmt.Errorf("new knownhosts [%s] failed: %v", path, err)
				return
			}
			cb = func(host string, remote net.Addr, key ssh.PublicKey) error {
				err := kh(host, remote, key)
				if knownhosts.IsHostKeyChanged(err) {
					fmt.Fprintf(os.Stderr, "\033[0;31m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n"+
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
					return err
				} else if knownhosts.IsHostUnknown(err) {
					return addHostKey(path, host, remote, key)
				}
				return err
			}
		})
		return cb, kh, err
	}
}()

type sshSigner struct {
	path   string
	priKey []byte
	pubKey ssh.PublicKey
	signer ssh.Signer
}

func (s *sshSigner) PublicKey() ssh.PublicKey {
	return s.pubKey
}

func (s *sshSigner) initSigner() error {
	if s.signer != nil {
		return nil
	}
	prompt := fmt.Sprintf("Enter passphrase for key '%s': ", s.path)
	for i := 0; i < 3; i++ {
		secret, err := readSecret(prompt)
		if err != nil {
			return err
		}
		if len(secret) == 0 {
			continue
		}
		s.signer, err = ssh.ParsePrivateKeyWithPassphrase(s.priKey, secret)
		if err == x509.IncorrectPasswordError {
			continue
		}
		if err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("passphrase incorrect")
}

func (s *sshSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	if err := s.initSigner(); err != nil {
		return nil, err
	}
	debug("sign without algorithm: %s", ssh.FingerprintSHA256(s.pubKey))
	return s.signer.Sign(rand, data)
}

func (s *sshSigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	if err := s.initSigner(); err != nil {
		return nil, err
	}
	if signer, ok := s.signer.(ssh.AlgorithmSigner); ok {
		debug("sign with algorithm [%s]: %s", algorithm, ssh.FingerprintSHA256(s.pubKey))
		return signer.SignWithAlgorithm(rand, data, algorithm)
	}
	debug("sign without algorithm: %s", ssh.FingerprintSHA256(s.pubKey))
	return s.signer.Sign(rand, data)
}

func newPassphraseSigner(path string, priKey []byte, err *ssh.PassphraseMissingError) (*sshSigner, error) {
	pubKey := err.PublicKey
	if pubKey == nil {
		pubPath := path + ".pub"
		pubData, err := os.ReadFile(pubPath)
		if err != nil {
			return nil, fmt.Errorf("read public key [%s] failed: %v", pubPath, err)
		}
		pubKey, _, _, _, err = ssh.ParseAuthorizedKey(pubData)
		if err != nil {
			return nil, fmt.Errorf("parse public key [%s] failed: %v", pubPath, err)
		}
	}
	return &sshSigner{path: path, priKey: priKey, pubKey: pubKey}, nil
}

func isFileExist(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}
	return true
}

func getSigner(dest string, path string) (*sshSigner, error) {
	path = resolveHomeDir(path)
	privateKey, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key [%s] failed: %v", path, err)
	}
	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		if e, ok := err.(*ssh.PassphraseMissingError); ok {
			if passphrase := getExConfig(dest, "Passphrase"); passphrase != "" {
				signer, err = ssh.ParsePrivateKeyWithPassphrase(privateKey, []byte(passphrase))
			} else {
				return newPassphraseSigner(path, privateKey, e)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("parse private key [%s] failed: %v", path, err)
		}
	}
	return &sshSigner{path: path, pubKey: signer.PublicKey(), signer: signer}, nil
}

func readSecret(prompt string) (secret []byte, err error) {
	fmt.Fprintf(os.Stderr, "%s", prompt)
	defer fmt.Fprintf(os.Stderr, "\r\n")

	stdin, closer, err := getKeyboardInput()
	if err != nil {
		return nil, err
	}
	defer closer()

	return term.ReadPassword(int(stdin.Fd()))
}

func getPasswordAuthMethod(args *sshArgs, host, user string) ssh.AuthMethod {
	if strings.ToLower(getOptionConfig(args, "PasswordAuthentication")) == "no" {
		debug("disable auth method: password authentication")
		return nil
	}

	idx := 0
	rememberPassword := false
	return ssh.RetryableAuthMethod(ssh.PasswordCallback(func() (string, error) {
		idx++
		if idx == 1 {
			if password := getExConfig(args.Destination, "Password"); password != "" {
				rememberPassword = true
				debug("trying the password configuration for %s", args.Destination)
				return password, nil
			}
		} else if idx == 2 && rememberPassword {
			debug("the password configuration for %s is incorrect", args.Destination)
		}
		secret, err := readSecret(fmt.Sprintf("%s@%s's password: ", user, host))
		if err != nil {
			return "", err
		}
		return string(secret), nil
	}), 3)
}

func readQuestionAnswerConfig(dest string, idx int, question string) string {
	qhex := hex.EncodeToString([]byte(question))
	debug("the hex code for question '%s' is %s", question, qhex)
	if answer := getExConfig(dest, qhex); answer != "" {
		return answer
	}

	qkey := fmt.Sprintf("QuestionAnswer%d", idx)
	debug("the configuration key for question '%s' is %s", question, qkey)
	if answer := getExConfig(dest, qkey); answer != "" {
		return answer
	}

	return ""
}

func getKeyboardInteractiveAuthMethod(args *sshArgs, host, user string) ssh.AuthMethod {
	if strings.ToLower(getOptionConfig(args, "KbdInteractiveAuthentication")) == "no" {
		debug("disable auth method: keyboard interactive authentication")
		return nil
	}

	idx := 0
	questionSet := make(map[string]struct{})
	return ssh.RetryableAuthMethod(ssh.KeyboardInteractive(
		func(name, instruction string, questions []string, echos []bool) ([]string, error) {
			var answers []string
			for _, question := range questions {
				idx++
				if _, ok := questionSet[question]; !ok {
					questionSet[question] = struct{}{}
					answer := readQuestionAnswerConfig(args.Destination, idx, question)
					if answer != "" {
						answers = append(answers, answer)
						continue
					}
				}
				secret, err := readSecret(fmt.Sprintf("(%s@%s) %s", user, host, strings.ReplaceAll(question, "\n", "\r\n")))
				if err != nil {
					return nil, err
				}
				answers = append(answers, string(secret))
			}
			return answers, nil
		}), 3)
}

var getDefaultSigners = func() func() []*sshSigner {
	var once sync.Once
	var signers []*sshSigner
	return func() []*sshSigner {
		once.Do(func() {
			for _, name := range []string{"id_rsa", "id_ecdsa", "id_ecdsa_sk", "id_ed25519", "id_ed25519_sk", "identity"} {
				path := filepath.Join(userHomeDir, ".ssh", name)
				if !isFileExist(path) {
					continue
				}
				signer, err := getSigner(name, path)
				if err != nil {
					warning("%s", err)
				} else {
					signers = append(signers, signer)
				}
			}
		})
		return signers
	}
}()

func getPublicKeysAuthMethod(args *sshArgs) ssh.AuthMethod {
	if strings.ToLower(getOptionConfig(args, "PubkeyAuthentication")) == "no" {
		debug("disable auth method: public key authentication")
		return nil
	}

	var pubKeySigners []ssh.Signer
	fingerprints := make(map[string]struct{})
	addPubKeySigners := func(signers []*sshSigner) {
		for _, signer := range signers {
			fingerprint := ssh.FingerprintSHA256(signer.PublicKey())
			if _, ok := fingerprints[fingerprint]; !ok {
				debug("will attempt key: %s %s %s", signer.path, signer.pubKey.Type(), ssh.FingerprintSHA256(signer.pubKey))
				fingerprints[fingerprint] = struct{}{}
				pubKeySigners = append(pubKeySigners, signer)
			}
		}
	}

	if agentClient := getAgentClient(); agentClient != nil {
		signers, err := agentClient.Signers()
		if err != nil {
			warning("get ssh agent signers failed: %v", err)
		} else {
			for _, signer := range signers {
				addPubKeySigners([]*sshSigner{{path: "ssh-agent", pubKey: signer.PublicKey(), signer: signer}})
			}
		}
	}

	if len(args.Identity.values) > 0 {
		for _, identity := range args.Identity.values {
			signer, err := getSigner(args.Destination, identity)
			if err != nil {
				warning("%s", err)
				continue
			}
			addPubKeySigners([]*sshSigner{signer})
		}
	} else {
		identities := getAllConfig(args.Destination, "IdentityFile")
		if len(identities) == 0 {
			addPubKeySigners(getDefaultSigners())
		} else {
			for _, identity := range identities {
				signer, err := getSigner(args.Destination, identity)
				if err != nil {
					warning("%s", err)
					continue
				}
				addPubKeySigners([]*sshSigner{signer})
			}
		}
	}

	if len(pubKeySigners) == 0 {
		return nil
	}
	return ssh.PublicKeys(pubKeySigners...)
}

func getAuthMethods(args *sshArgs, host, user string) []ssh.AuthMethod {
	var authMethods []ssh.AuthMethod
	if authMethod := getPublicKeysAuthMethod(args); authMethod != nil {
		debug("add auth method: public key authentication")
		authMethods = append(authMethods, authMethod)
	}
	if authMethod := getKeyboardInteractiveAuthMethod(args, host, user); authMethod != nil {
		debug("add auth method: keyboard interactive authentication")
		authMethods = append(authMethods, authMethod)
	}
	if authMethod := getPasswordAuthMethod(args, host, user); authMethod != nil {
		debug("add auth method: password authentication")
		authMethods = append(authMethods, authMethod)
	}
	return authMethods
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
	debug("exec proxy command: %s", command)

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

func dialWithTimeout(client *ssh.Client, network, addr string, timeout time.Duration) (conn net.Conn, err error) {
	done := make(chan struct{}, 1)
	go func() {
		defer close(done)
		conn, err = client.Dial(network, addr)
		done <- struct{}{}
	}()
	select {
	case <-time.After(timeout):
		err = fmt.Errorf("dial [%s] timeout", addr)
	case <-done:
	}
	return
}

type connWithTimeout struct {
	net.Conn
	timeout   time.Duration
	firstRead bool
}

func (c *connWithTimeout) Read(b []byte) (n int, err error) {
	if !c.firstRead {
		return c.Conn.Read(b)
	}
	done := make(chan struct{}, 1)
	go func() {
		defer close(done)
		n, err = c.Conn.Read(b)
		done <- struct{}{}
	}()
	select {
	case <-time.After(c.timeout):
		err = fmt.Errorf("first read timeout")
	case <-done:
	}
	c.firstRead = false
	return
}

func sshConnect(args *sshArgs, client *ssh.Client, proxy string) (*ssh.Client, error) {
	param, err := getLoginParam(args)
	if err != nil {
		return nil, err
	}
	authMethods := getAuthMethods(args, param.host, param.user)
	cb, kh, err := getHostKeyCallback()
	if err != nil {
		return nil, err
	}
	config := &ssh.ClientConfig{
		User:              param.user,
		Auth:              authMethods,
		Timeout:           10 * time.Second,
		HostKeyCallback:   cb,
		HostKeyAlgorithms: kh.HostKeyAlgorithms(param.addr),
		BannerCallback: func(banner string) error {
			_, err := fmt.Fprint(os.Stderr, strings.ReplaceAll(banner, "\n", "\r\n"))
			return err
		},
	}

	proxyConnect := func(client *ssh.Client, proxy string) (*ssh.Client, error) {
		debug("login to [%s], addr: %s", args.Destination, param.addr)
		conn, err := dialWithTimeout(client, "tcp", param.addr, 10*time.Second)
		if err != nil {
			return nil, fmt.Errorf("proxy [%s] dial tcp [%s] failed: %v", proxy, param.addr, err)
		}
		ncc, chans, reqs, err := ssh.NewClientConn(&connWithTimeout{conn, config.Timeout, true}, param.addr, config)
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
		debug("login to [%s], addr: %s", args.Destination, param.addr)
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
		debug("login to [%s], addr: %s", args.Destination, param.addr)
		conn, err := net.DialTimeout("tcp", param.addr, config.Timeout)
		if err != nil {
			return nil, fmt.Errorf("dial tcp [%s] failed: %v", param.addr, err)
		}
		ncc, chans, reqs, err := ssh.NewClientConn(&connWithTimeout{conn, config.Timeout, true}, param.addr, config)
		if err != nil {
			return nil, fmt.Errorf("new conn [%s] failed: %v", param.addr, err)
		}
		return ssh.NewClient(ncc, chans, reqs), nil
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
		value, err := strconv.Atoi(getOptionConfig(args, option))
		if err != nil {
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

func wrapStdIO(serverIn io.WriteCloser, serverOut io.Reader, tty bool) {
	win := runtime.GOOS == "windows"
	forwardIO := func(reader io.Reader, writer io.WriteCloser, oldVal, newVal []byte) {
		defer writer.Close()
		buffer := make([]byte, 32*1024)
		for {
			n, err := reader.Read(buffer)
			if n > 0 {
				buf := buffer[:n]
				if win && !tty {
					buf = bytes.ReplaceAll(buf, oldVal, newVal)
				}
				w := 0
				for w < len(buf) {
					n, err := writer.Write(buf[w:])
					if err != nil {
						warning("wrap stdio write failed: %v", err)
						return
					}
					w += n
				}
			}
			if err == io.EOF {
				if win && tty {
					_, _ = writer.Write([]byte{0x1A}) // ctrl + z
					continue
				}
				break
			}
			if err != nil {
				warning("wrap stdio read failed: %v", err)
				return
			}
		}
	}
	go forwardIO(os.Stdin, serverIn, []byte("\r\n"), []byte("\n"))
	go forwardIO(serverOut, os.Stdout, []byte("\n"), []byte("\r\n"))
}

func sshAgentForward(args *sshArgs, client *ssh.Client, session *ssh.Session) {
	agentClient := getAgentClient()
	if agentClient == nil {
		return
	}
	if args.NoForwardAgent || !args.ForwardAgent && strings.ToLower(getOptionConfig(args, "ForwardAgent")) != "yes" {
		closeAgentClient()
		return
	}
	if err := agent.ForwardToAgent(client, agentClient); err != nil {
		warning("forward to agent failed: %v", err)
		return
	}
	if err := agent.RequestAgentForwarding(session); err != nil {
		warning("request agent forwarding failed: %v", err)
		return
	}
	debug("request ssh agent forwarding success")
}

func sshLogin(args *sshArgs, tty bool) (client *ssh.Client, session *ssh.Session, err error) {
	defer func() {
		if err != nil {
			if session != nil {
				session.Close()
			}
			if client != nil {
				client.Close()
			}
		}
	}()

	cleanupAfterLogined = append(cleanupAfterLogined, func() {
		getDefaultSigners = nil
		getHostKeyCallback = nil
	})

	// ssh login
	client, err = sshConnect(args, nil, "")
	if err != nil {
		return
	}

	// keep alive
	go keepAlive(client, args)

	// no command
	if args.NoCommand || args.StdioForward != "" {
		return
	}

	// new session
	session, err = client.NewSession()
	if err != nil {
		err = fmt.Errorf("ssh new session failed: %v", err)
		return
	}
	session.Stderr = os.Stderr

	// session input and output
	serverIn, err := session.StdinPipe()
	if err != nil {
		err = fmt.Errorf("stdin pipe failed: %v", err)
		return
	}
	serverOut, err := session.StdoutPipe()
	if err != nil {
		err = fmt.Errorf("stdout pipe failed: %v", err)
		return
	}

	// ssh agent forward
	sshAgentForward(args, client, session)

	// no tty
	if !tty {
		wrapStdIO(serverIn, serverOut, tty)
		return
	}

	// request pty session
	width, height, err := getTerminalSize()
	if err != nil {
		err = fmt.Errorf("get terminal size failed: %v", err)
		return
	}
	if err = session.RequestPty("xterm-256color", height, width, ssh.TerminalModes{}); err != nil {
		err = fmt.Errorf("request pty failed: %v", err)
		return
	}

	// disable trzsz ( trz / tsz )
	if strings.ToLower(getExOptionConfig(args, "EnableTrzsz")) == "no" {
		wrapStdIO(serverIn, serverOut, tty)
		onTerminalResize(func(width, height int) { _ = session.WindowChange(height, width) })
		return
	}

	// support trzsz ( trz / tsz )
	trzsz.SetAffectedByWindows(false)
	if args.Relay || isNoGUI() {
		// run as a relay
		trzszRelay := trzsz.NewTrzszRelay(os.Stdin, os.Stdout, serverIn, serverOut, trzsz.TrzszOptions{
			DetectTraceLog: args.TraceLog,
		})
		// reset terminal size on resize
		onTerminalResize(func(width, height int) { _ = session.WindowChange(height, width) })
		// setup tunnel connect
		trzszRelay.SetTunnelConnector(func(port int) net.Conn {
			conn, _ := dialWithTimeout(client, "tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
			return conn
		})
	} else {
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

		// reset terminal size on resize
		onTerminalResize(func(width, height int) {
			trzszFilter.SetTerminalColumns(int32(width))
			_ = session.WindowChange(height, width)
		})

		// setup default paths
		trzszFilter.SetDefaultUploadPath(userConfig.defaultUploadPath)
		trzszFilter.SetDefaultDownloadPath(userConfig.defaultDownloadPath)

		// setup tunnel connect
		trzszFilter.SetTunnelConnector(func(port int) net.Conn {
			conn, _ := dialWithTimeout(client, "tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
			return conn
		})
	}

	return
}

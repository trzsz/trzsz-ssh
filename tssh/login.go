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
	"bufio"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alessio/shellescape"
	"github.com/skeema/knownhosts"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

var enableDebugLogging bool = false
var envbleWarningLogging bool = true

func debug(format string, a ...any) {
	if !enableDebugLogging {
		return
	}
	fmt.Fprintf(os.Stderr, fmt.Sprintf("\033[0;36mdebug:\033[0m %s\r\n", format), a...)
}

var warning = func(format string, a ...any) {
	if !envbleWarningLogging {
		return
	}
	fmt.Fprintf(os.Stderr, fmt.Sprintf("\033[0;33mWarning: %s\033[0m\r\n", format), a...)
}

type sshParam struct {
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

func getSshParam(args *sshArgs) (*sshParam, error) {
	param := &sshParam{}

	// login dest
	destUser, destHost, destPort := parseDestination(args.Destination)
	args.Destination = destHost

	// login host
	param.host = destHost
	if hostName := getConfig(destHost, "HostName"); hostName != "" {
		var err error
		param.host, err = expandTokens(hostName, args, param, "%h")
		if err != nil {
			return nil, err
		}
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

	// expand proxy
	var err error
	if param.command != "" {
		param.command, err = expandTokens(param.command, args, param, "%hnpr")
		if err != nil {
			return nil, fmt.Errorf("expand ProxyCommand [%s] failed: %v", param.command, err)
		}
	}
	for i := 0; i < len(param.proxy); i++ {
		param.proxy[i], err = expandTokens(param.proxy[i], args, param, "%hnpr")
		if err != nil {
			return nil, fmt.Errorf("expand ProxyJump [%s] failed: %v", param.proxy[i], err)
		}
	}

	return param, nil
}

var acceptHostKeys []string
var sshLoginSuccess atomic.Bool

func ensureNewline(file *os.File) error {
	if _, err := file.Seek(-1, io.SeekEnd); err != nil {
		return nil
	}
	buf := make([]byte, 1)
	if n, err := file.Read(buf); err != nil || n != 1 || buf[0] == '\n' {
		return nil
	}
	if _, err := file.Write([]byte("\n")); err != nil {
		return err
	}
	return nil
}

func writeKnownHost(path, host string, remote net.Addr, key ssh.PublicKey) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := ensureNewline(file); err != nil {
		return err
	}

	hostNormalized := knownhosts.Normalize(host)
	if strings.ContainsAny(hostNormalized, "\t ") {
		return fmt.Errorf("host '%s' contains spaces", hostNormalized)
	}
	line := knownhosts.Line([]string{hostNormalized}, key) + "\n"
	return writeAll(file, []byte(line))
}

func addHostKey(path, host string, remote net.Addr, key ssh.PublicKey, ask bool) error {
	keyNormalizedLine := knownhosts.Line([]string{host}, key)
	for _, acceptKey := range acceptHostKeys {
		if acceptKey == keyNormalizedLine {
			return nil
		}
	}

	if ask {
		if sshLoginSuccess.Load() {
			fmt.Fprintf(os.Stderr, "\r\n\033[0;31mThe public key of the remote server has changed after login.\033[0m\r\n")
			return fmt.Errorf("host key changed")
		}

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
	}

	acceptHostKeys = append(acceptHostKeys, keyNormalizedLine)

	if err := writeKnownHost(path, host, remote, key); err != nil {
		warning("Failed to add the host to the list of known hosts (%s): %v", path, err)
		return nil
	}

	warning("Permanently added '%s' (%s) to the list of known hosts.", host, key.Type())
	return nil
}

func getHostKeyCallback(args *sshArgs, param *sshParam) (ssh.HostKeyCallback, knownhosts.HostKeyCallback, error) {
	primaryPath := ""
	var files []string
	addKnownHostsFiles := func(key string, user bool) error {
		knownHostsFiles := getOptionConfigSplits(args, key)
		if len(knownHostsFiles) == 0 {
			debug("%s is empty", key)
			return nil
		}
		if len(knownHostsFiles) == 1 && strings.ToLower(knownHostsFiles[0]) == "none" {
			debug("%s is none", key)
			return nil
		}
		for _, path := range knownHostsFiles {
			var resolvedPath string
			if user {
				expandedPath, err := expandTokens(path, args, param, "%CdhijkLlnpru")
				if err != nil {
					return fmt.Errorf("expand UserKnownHostsFile [%s] failed: %v", path, err)
				}
				resolvedPath = resolveHomeDir(expandedPath)
				if primaryPath == "" {
					primaryPath = resolvedPath
				}
			} else {
				resolvedPath = path
			}
			if !isFileExist(resolvedPath) {
				debug("%s [%s] does not exist", key, resolvedPath)
				continue
			}
			if !canReadFile(resolvedPath) {
				if user {
					warning("%s [%s] can't be read", key, resolvedPath)
				} else {
					debug("%s [%s] can't be read", key, resolvedPath)
				}
				continue
			}
			debug("add %s: %s", key, resolvedPath)
			files = append(files, resolvedPath)
		}
		return nil
	}
	if err := addKnownHostsFiles("UserKnownHostsFile", true); err != nil {
		return nil, nil, err
	}
	if err := addKnownHostsFiles("GlobalKnownHostsFile", false); err != nil {
		return nil, nil, err
	}

	kh, err := knownhosts.New(files...)
	if err != nil {
		return nil, nil, fmt.Errorf("new knownhosts failed: %v", err)
	}

	cb := func(host string, remote net.Addr, key ssh.PublicKey) error {
		err := kh(host, remote, key)
		if err == nil {
			return nil
		}
		strictHostKeyChecking := strings.ToLower(getOptionConfig(args, "StrictHostKeyChecking"))
		if knownhosts.IsHostKeyChanged(err) {
			path := primaryPath
			if path == "" {
				path = "~/.ssh/known_hosts"
			}
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
		} else if knownhosts.IsHostUnknown(err) && primaryPath != "" {
			ask := true
			switch strictHostKeyChecking {
			case "yes":
				return err
			case "accept-new", "no", "off":
				ask = false
			}
			return addHostKey(primaryPath, host, remote, key, ask)
		}
		switch strictHostKeyChecking {
		case "no", "off":
			return nil
		default:
			return err
		}
	}

	return cb, kh, err
}

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
	if enableDebugLogging {
		debug("sign without algorithm: %s", ssh.FingerprintSHA256(s.pubKey))
	}
	return s.signer.Sign(rand, data)
}

func (s *sshSigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	if err := s.initSigner(); err != nil {
		return nil, err
	}
	if signer, ok := s.signer.(ssh.AlgorithmSigner); ok {
		if enableDebugLogging {
			debug("sign with algorithm [%s]: %s", algorithm, ssh.FingerprintSHA256(s.pubKey))
		}
		return signer.SignWithAlgorithm(rand, data, algorithm)
	}
	if enableDebugLogging {
		debug("sign without algorithm: %s", ssh.FingerprintSHA256(s.pubKey))
	}
	return s.signer.Sign(rand, data)
}

func newPassphraseSigner(path string, priKey []byte, err *ssh.PassphraseMissingError) *sshSigner {
	pubKey := err.PublicKey
	if pubKey == nil {
		pubPath := path + ".pub"
		pubData, err := os.ReadFile(pubPath)
		if err != nil {
			warning("read public key [%s] failed: %v", pubPath, err)
			return nil
		}
		pubKey, _, _, _, err = ssh.ParseAuthorizedKey(pubData)
		if err != nil {
			warning("parse public key [%s] failed: %v", pubPath, err)
			return nil
		}
	}
	return &sshSigner{path: path, priKey: priKey, pubKey: pubKey}
}

func isFileExist(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}
	return true
}

func canReadFile(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	file.Close()
	return true
}

func getSigner(dest string, path string) *sshSigner {
	path = resolveHomeDir(path)
	privateKey, err := os.ReadFile(path)
	if err != nil {
		warning("read private key [%s] failed: %v", path, err)
		return nil
	}
	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		if e, ok := err.(*ssh.PassphraseMissingError); ok {
			if passphrase := getSecretConfig(dest, "Passphrase"); passphrase != "" {
				signer, err = ssh.ParsePrivateKeyWithPassphrase(privateKey, []byte(passphrase))
			} else {
				return newPassphraseSigner(path, privateKey, e)
			}
		}
		if err != nil {
			warning("parse private key [%s] failed: %v", path, err)
			return nil
		}
	}
	return &sshSigner{path: path, pubKey: signer.PublicKey(), signer: signer}
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
			password := args.Option.get("Password")
			if password == "" {
				password = getSecretConfig(args.Destination, "Password")
			}
			if password != "" {
				rememberPassword = true
				debug("trying the password configuration for '%s'", args.Destination)
				return password, nil
			}
		} else if idx == 2 && rememberPassword {
			warning("the password configuration for '%s' is incorrect", args.Destination)
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
	if answer := getSecretConfig(dest, qhex); answer != "" {
		return answer
	}

	if secret := getSecretConfig(dest, "totp"+qhex); secret != "" {
		if answer := getTotpCode(secret); answer != "" {
			return answer
		}
	}

	if command := getSecretConfig(dest, "otp"+qhex); command != "" {
		if answer := getOtpCommandOutput(command, question); answer != "" {
			return answer
		}
	}

	qkey := fmt.Sprintf("QuestionAnswer%d", idx)
	debug("the configuration key for question '%s' is %s", question, qkey)
	if answer := getSecretConfig(dest, qkey); answer != "" {
		return answer
	}

	qsecret := fmt.Sprintf("TotpSecret%d", idx)
	debug("the totp secret key for question '%s' is %s", question, qsecret)
	if secret := getSecretConfig(dest, qsecret); secret != "" {
		if answer := getTotpCode(secret); answer != "" {
			return answer
		}
	}

	qcmd := fmt.Sprintf("OtpCommand%d", idx)
	debug("the otp command key for question '%s' is %s", question, qcmd)
	if command := getSecretConfig(dest, qcmd); command != "" {
		if answer := getOtpCommandOutput(command, question); answer != "" {
			return answer
		}
	}

	return ""
}

func getKeyboardInteractiveAuthMethod(args *sshArgs, host, user string) ssh.AuthMethod {
	if strings.ToLower(getOptionConfig(args, "KbdInteractiveAuthentication")) == "no" {
		debug("disable auth method: keyboard interactive authentication")
		return nil
	}

	idx := 0
	questionSeen := make(map[string]struct{})
	questionTried := make(map[string]struct{})
	questionWarned := make(map[string]struct{})
	return ssh.RetryableAuthMethod(ssh.KeyboardInteractive(
		func(name, instruction string, questions []string, echos []bool) ([]string, error) {
			var answers []string
			for _, question := range questions {
				idx++
				if _, seen := questionSeen[question]; !seen {
					questionSeen[question] = struct{}{}
					answer := readQuestionAnswerConfig(args.Destination, idx, question)
					if answer != "" {
						questionTried[question] = struct{}{}
						answers = append(answers, answer)
						continue
					}
				} else if _, tried := questionTried[question]; tried {
					if _, warned := questionWarned[question]; !warned {
						questionWarned[question] = struct{}{}
						warning("the question answer configuration of '%s' for '%s' is incorrect", question, args.Destination)
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
				if signer := getSigner(name, path); signer != nil {
					signers = append(signers, signer)
				}
			}
		})
		return signers
	}
}()

func getPublicKeysAuthMethod(args *sshArgs, param *sshParam) ssh.AuthMethod {
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
				if enableDebugLogging {
					debug("will attempt key: %s %s %s", signer.path, signer.pubKey.Type(), ssh.FingerprintSHA256(signer.pubKey))
				}
				fingerprints[fingerprint] = struct{}{}
				pubKeySigners = append(pubKeySigners, signer)
			}
		}
	}

	if agentClient := getAgentClient(args, param); agentClient != nil {
		signers, err := agentClient.Signers()
		if err != nil {
			warning("get ssh agent signers failed: %v", err)
		} else {
			for _, signer := range signers {
				addPubKeySigners([]*sshSigner{{path: "ssh-agent", pubKey: signer.PublicKey(), signer: signer}})
			}
		}
	}

	identities := args.Identity.values
	for _, identity := range getAllOptionConfig(args, "IdentityFile") {
		expandedIdentity, err := expandTokens(identity, args, param, "%CdhijkLlnpru")
		if err != nil {
			warning("expand IdentityFile [%s] failed: %v", identity, err)
			continue
		}
		identities = append(identities, expandedIdentity)
	}

	if len(identities) == 0 {
		addPubKeySigners(getDefaultSigners())
	} else {
		for _, identity := range identities {
			if signer := getSigner(args.Destination, identity); signer != nil {
				addPubKeySigners([]*sshSigner{signer})
			}
		}
	}

	if len(pubKeySigners) == 0 {
		return nil
	}
	return ssh.PublicKeys(pubKeySigners...)
}

func getAuthMethods(args *sshArgs, param *sshParam) []ssh.AuthMethod {
	var authMethods []ssh.AuthMethod
	if authMethod := getPublicKeysAuthMethod(args, param); authMethod != nil {
		debug("add auth method: public key authentication")
		authMethods = append(authMethods, authMethod)
	}
	if authMethod := getKeyboardInteractiveAuthMethod(args, param.host, param.user); authMethod != nil {
		debug("add auth method: keyboard interactive authentication")
		authMethods = append(authMethods, authMethod)
	}
	if authMethod := getPasswordAuthMethod(args, param.host, param.user); authMethod != nil {
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

func execProxyCommand(args *sshArgs, param *sshParam) (net.Conn, string, error) {
	command, err := expandTokens(param.command, args, param, "%hnpr")
	if err != nil {
		return nil, param.command, err
	}
	command = resolveHomeDir(command)
	debug("exec proxy command: %s", command)

	argv, err := splitCommandLine(command)
	if err != nil || len(argv) == 0 {
		return nil, command, fmt.Errorf("split proxy command failed: %v", err)
	}
	if enableDebugLogging {
		for i, arg := range argv {
			debug("proxy command argv[%d] = %s", i, arg)
		}
	}
	cmd := exec.Command(argv[0], argv[1:]...)

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

func execLocalCommand(args *sshArgs, param *sshParam) {
	if strings.ToLower(getOptionConfig(args, "PermitLocalCommand")) != "yes" {
		return
	}
	localCmd := getOptionConfig(args, "LocalCommand")
	if localCmd == "" {
		return
	}
	expandedCmd, err := expandTokens(localCmd, args, param, "%CdfHhIijKkLlnprTtu")
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

func parseRemoteCommand(args *sshArgs, param *sshParam) (string, error) {
	command := args.Option.get("RemoteCommand")
	if args.Command != "" && command != "" && strings.ToLower(command) != "none" {
		return "", fmt.Errorf("cannot execute command-line and remote command")
	}
	if args.Command != "" {
		if len(args.Argument) == 0 {
			return args.Command, nil
		}
		return shellescape.QuoteCommand(append([]string{args.Command}, args.Argument...)), nil
	}
	if strings.ToLower(command) == "none" {
		return "", nil
	}
	if command == "" {
		command = getConfig(args.Destination, "RemoteCommand")
	}
	expandedCmd, err := expandTokens(command, args, param, "%CdhijkLlnpru")
	if err != nil {
		return "", fmt.Errorf("expand RemoteCommand [%s] failed: %v", command, err)
	}
	return expandedCmd, nil
}

func parseCmdAndTTY(args *sshArgs, param *sshParam) (cmd string, tty bool, err error) {
	cmd, err = parseRemoteCommand(args, param)
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

	requestTTY := getConfig(args.Destination, "RequestTTY")
	switch strings.ToLower(requestTTY) {
	case "", "auto":
		tty = isTerminal && (cmd == "")
	case "no":
		tty = false
	case "force":
		tty = true
	case "yes":
		tty = isTerminal
	default:
		err = fmt.Errorf("unknown RequestTTY option: %s", requestTTY)
	}
	return
}

var lastServerAliveTime atomic.Pointer[time.Time]

type connWithTimeout struct {
	net.Conn
	timeout   time.Duration
	firstRead bool
}

func (c *connWithTimeout) Read(b []byte) (n int, err error) {
	if !c.firstRead {
		n, err = c.Conn.Read(b)
		if err == nil {
			now := time.Now()
			lastServerAliveTime.Store(&now)
		}
		return
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

func setupLogLevel(args *sshArgs) func() {
	previousDebug := enableDebugLogging
	previousWarning := envbleWarningLogging
	reset := func() {
		enableDebugLogging = previousDebug
		envbleWarningLogging = previousWarning
	}
	if args.Debug {
		enableDebugLogging = true
		envbleWarningLogging = true
		return reset
	}
	switch strings.ToLower(getOptionConfig(args, "LogLevel")) {
	case "quiet", "fatal", "error":
		enableDebugLogging = false
		envbleWarningLogging = false
	case "debug", "debug1", "debug2", "debug3":
		enableDebugLogging = true
		envbleWarningLogging = true
	case "info", "verbose":
		enableDebugLogging = false
		envbleWarningLogging = true
	}
	return reset
}

func getNetworkAddressFamily(args *sshArgs) string {
	if args.IPv4Only {
		if args.IPv6Only {
			return "tcp"
		}
		return "tcp4"
	}
	if args.IPv6Only {
		return "tcp6"
	}
	switch strings.ToLower(getOptionConfig(args, "AddressFamily")) {
	case "inet":
		return "tcp4"
	case "inet6":
		return "tcp6"
	default:
		return "tcp"
	}
}

func sshConnect(args *sshArgs, client SshClient, proxy string) (SshClient, *sshParam, bool, error) {
	param, err := getSshParam(args)
	if err != nil {
		return nil, nil, false, err
	}

	resetLogLevel := setupLogLevel(args)
	defer resetLogLevel()

	if client := connectViaControl(args, param); client != nil {
		return client, param, true, nil
	}

	authMethods := getAuthMethods(args, param)
	cb, kh, err := getHostKeyCallback(args, param)
	if err != nil {
		return nil, param, false, err
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

	if err := setupCiphersConfig(args, config); err != nil {
		return nil, param, false, err
	}

	network := getNetworkAddressFamily(args)

	proxyConnect := func(client SshClient, proxy string) (SshClient, *sshParam, bool, error) {
		debug("login to [%s], addr: %s", args.Destination, param.addr)
		conn, err := client.DialTimeout(network, param.addr, 10*time.Second)
		if err != nil {
			return nil, param, false, fmt.Errorf("proxy [%s] dial tcp [%s] failed: %v", proxy, param.addr, err)
		}
		ncc, chans, reqs, err := ssh.NewClientConn(&connWithTimeout{conn, config.Timeout, true}, param.addr, config)
		if err != nil {
			return nil, param, false, fmt.Errorf("proxy [%s] new conn [%s] failed: %v", proxy, param.addr, err)
		}
		debug("login to [%s] success", args.Destination)
		return sshNewClient(ncc, chans, reqs), param, false, nil
	}

	// has parent client
	if client != nil {
		return proxyConnect(client, proxy)
	}

	// proxy command
	if param.command != "" {
		debug("login to [%s], addr: %s", args.Destination, param.addr)
		conn, cmd, err := execProxyCommand(args, param)
		if err != nil {
			return nil, param, false, fmt.Errorf("exec proxy command [%s] failed: %v", cmd, err)
		}
		ncc, chans, reqs, err := ssh.NewClientConn(conn, param.addr, config)
		if err != nil {
			return nil, param, false, fmt.Errorf("proxy command [%s] new conn [%s] failed: %v", cmd, param.addr, err)
		}
		debug("login to [%s] success", args.Destination)
		return sshNewClient(ncc, chans, reqs), param, false, nil
	}

	// no proxy
	if len(param.proxy) == 0 {
		debug("login to [%s], addr: %s", args.Destination, param.addr)
		conn, err := net.DialTimeout(network, param.addr, config.Timeout)
		if err != nil {
			return nil, param, false, fmt.Errorf("dial tcp [%s] failed: %v", param.addr, err)
		}
		ncc, chans, reqs, err := ssh.NewClientConn(&connWithTimeout{conn, config.Timeout, true}, param.addr, config)
		if err != nil {
			return nil, param, false, fmt.Errorf("new conn [%s] failed: %v", param.addr, err)
		}
		debug("login to [%s] success", args.Destination)
		return sshNewClient(ncc, chans, reqs), param, false, nil
	}

	// has proxies
	var proxyClient SshClient
	for _, proxy = range param.proxy {
		proxyClient, _, _, err = sshConnect(&sshArgs{Destination: proxy}, proxyClient, proxy)
		if err != nil {
			return nil, param, false, err
		}
	}
	return proxyConnect(proxyClient, proxy)
}

func keepAlive(client SshClient, args *sshArgs) {
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

	go func() {
		intervalTime := time.Duration(serverAliveInterval) * time.Second
		t := time.NewTicker(intervalTime)
		defer t.Stop()
		n := 0
		for range t.C {
			if lastTime := lastServerAliveTime.Load(); lastTime != nil && time.Since(*lastTime) < intervalTime {
				n = 0
				continue
			}
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
	}()
}

func sshAgentForward(args *sshArgs, param *sshParam, client SshClient, session SshSession) {
	if args.NoForwardAgent || !args.ForwardAgent && strings.ToLower(getOptionConfig(args, "ForwardAgent")) != "yes" {
		return
	}
	addr, err := getAgentAddr(args, param)
	if err != nil {
		warning("get agent addr failed: %v", err)
		return
	}
	if addr == "" {
		warning("forward agent but the socket address is not set")
		return
	}
	if err := forwardToRemote(client, addr); err != nil {
		warning("forward to agent [%s] failed: %v", addr, err)
		return
	}
	if err := requestAgentForwarding(session); err != nil {
		warning("request agent forwarding failed: %v", err)
		return
	}
	debug("request ssh agent forwarding success")
}

func sshTcpLogin(args *sshArgs) (ss *sshClientSession, udpMode int, err error) {
	ss = &sshClientSession{}
	defer func() {
		if err != nil {
			ss.Close()
		} else {
			sshLoginSuccess.Store(true)
			// execute local command if necessary
			execLocalCommand(args, ss.param)
		}
	}()

	// ssh login
	var control bool
	ss.client, ss.param, control, err = sshConnect(args, nil, "")
	if err != nil {
		return
	}

	// udp mode ?
	udpMode = getUdpMode(args)

	// parse cmd and tty
	ss.cmd, ss.tty, err = parseCmdAndTTY(args, ss.param)
	if err != nil {
		return
	}

	// keep alive
	if !control && udpMode == kUdpModeNo {
		keepAlive(ss.client, args)
	}

	// stdio forward runs as a proxy without port forwarding.
	// but udp mode requires a new session to start tsshd.
	if args.StdioForward != "" && udpMode == kUdpModeNo {
		return
	}

	// ssh port forwarding
	if !control && udpMode == kUdpModeNo {
		if err = sshForward(ss.client, args, ss.param); err != nil {
			return
		}
	}

	// session is useless without executing remote command.
	// but udp mode requires a new session to start tsshd.
	if args.NoCommand && udpMode == kUdpModeNo {
		return
	}

	// new session
	ss.session, err = ss.client.NewSession()
	if err != nil {
		err = fmt.Errorf("ssh new session failed: %v", err)
		return
	}

	// session input and output
	ss.serverIn, err = ss.session.StdinPipe()
	if err != nil {
		err = fmt.Errorf("stdin pipe failed: %v", err)
		return
	}
	ss.serverOut, err = ss.session.StdoutPipe()
	if err != nil {
		err = fmt.Errorf("stdout pipe failed: %v", err)
		return
	}
	ss.serverErr, err = ss.session.StderrPipe()
	if err != nil {
		err = fmt.Errorf("stderr pipe failed: %v", err)
		return
	}

	if !control && udpMode == kUdpModeNo {
		// ssh agent forward
		sshAgentForward(args, ss.param, ss.client, ss.session)
		// x11 forward
		sshX11Forward(args, ss.client, ss.session)
	}

	return
}

func sshLogin(args *sshArgs) (*sshClientSession, error) {
	ss, udpMode, err := sshTcpLogin(args)
	if err != nil {
		return nil, err
	}

	if udpMode != kUdpModeNo {
		ss, err = sshUdpLogin(args, ss, udpMode)
		if err != nil {
			return nil, err
		}

		// ssh port forwarding if not running as a proxy ( aka: not stdio forward ).
		if args.StdioForward == "" {
			if err := sshForward(ss.client, args, ss.param); err != nil {
				ss.Close()
				return nil, err
			}
		}

		// ssh agent forward and x11 forward
		// if not running as a proxy ( aka: not stdio forward ) and executing remote command
		if args.StdioForward == "" && !args.NoCommand {
			// ssh agent forward
			sshAgentForward(args, ss.param, ss.client, ss.session)
			// x11 forward
			sshX11Forward(args, ss.client, ss.session)
		}
	}

	// if running as a proxy ( aka: stdio forward ), or if not executing remote command,
	// then there is no need to initialize the session, so we return early here.
	if args.StdioForward != "" || args.NoCommand {
		return ss, nil
	}

	// send and set env
	term, err := sendAndSetEnv(args, ss.session)
	if err != nil {
		ss.Close()
		return nil, err
	}

	// not terminal or not tty
	if !isTerminal || !ss.tty {
		return ss, nil
	}

	// request pty session
	width, height, err := getTerminalSize()
	if err != nil {
		ss.Close()
		return nil, fmt.Errorf("get terminal size failed: %v", err)
	}
	if term == "" {
		term = os.Getenv("TERM")
		if term == "" {
			term = "xterm-256color"
		}
	}
	if err = ss.session.RequestPty(term, height, width, ssh.TerminalModes{}); err != nil {
		ss.Close()
		return nil, fmt.Errorf("request pty failed: %v", err)
	}

	return ss, nil
}

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
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type sshSigner interface {
	ssh.Signer
	getPath() string
}

type sshBaseSigner struct {
	path   string
	priKey []byte
	pubKey ssh.PublicKey
	signer ssh.Signer
}

type sshAlogSigner struct {
	*sshBaseSigner
	algos []string
}

func (s *sshAlogSigner) Algorithms() []string {
	return s.algos
}

func newSshSigner(path string, priKey []byte, pubKey ssh.PublicKey, signer ssh.Signer) sshSigner {
	baseSigner := &sshBaseSigner{path, priKey, pubKey, signer}

	if pubKey != nil {
		keyFormat := pubKey.Type()
		if keyFormat == ssh.KeyAlgoRSA || keyFormat == ssh.CertAlgoRSAv01 {
			// prefer rsa-sha2-512 over rsa-sha2-256
			return &sshAlogSigner{baseSigner, []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}}
		}
	}

	return baseSigner
}

func (s *sshBaseSigner) getPath() string {
	return s.path
}

func (s *sshBaseSigner) PublicKey() ssh.PublicKey {
	return s.pubKey
}

func (s *sshBaseSigner) initSigner() error {
	if s.signer != nil {
		return nil
	}
	prompt := fmt.Sprintf("Enter passphrase for key '%s': ", s.path)
	for range 3 {
		secret, err := readSecret(prompt)
		if err != nil {
			return err
		}
		if len(secret) == 0 {
			continue
		}
		s.signer, err = parsePrivateKeyWithPassphrase(s.priKey, secret)
		if err == x509.IncorrectPasswordError {
			continue
		}
		if skErr, ok := err.(*unhandledSecurityKeyError); ok {
			s.signer, err = parseSecurityKey(s.path, skErr)
		}
		if err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("passphrase incorrect")
}

func (s *sshBaseSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	if err := s.initSigner(); err != nil {
		return nil, err
	}

	if enableDebugLogging {
		debug("sign with key: %s %s", s.path, ssh.FingerprintSHA256(s.pubKey))
	}
	signature, err := s.signer.Sign(rand, data)
	if err != nil {
		warning("sign with [%s] failed: %v", s.path, err)
	}
	return signature, err
}

func (s *sshBaseSigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	if err := s.initSigner(); err != nil {
		return nil, err
	}

	if signer, ok := s.signer.(ssh.AlgorithmSigner); ok {
		if enableDebugLogging {
			debug("sign with key: %s %s %s", s.path, algorithm, ssh.FingerprintSHA256(s.pubKey))
		}
		signature, err := signer.SignWithAlgorithm(rand, data, algorithm)
		if err != nil {
			warning("sign with [%s] failed: %v", s.path, err)
		}
		return signature, err
	}

	return s.Sign(rand, data)
}

func parsePublicKey(path string) ssh.PublicKey {
	data, err := os.ReadFile(path)
	if err != nil {
		warning("read public key [%s] failed: %v", path, err)
		return nil
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		warning("parse public key [%s] failed: %v", path, err)
		return nil
	}
	return key
}

func newPassphraseSigner(path string, priKey []byte, err *ssh.PassphraseMissingError) sshSigner {
	pubKey := err.PublicKey
	if pubKey == nil {
		pubKey = parsePublicKey(path + ".pub")
		if pubKey == nil {
			return nil
		}
	}
	return newSshSigner(path, priKey, pubKey, nil)
}

func getSigner(param *sshParam, path string) sshSigner {
	path = resolveHomeDir(path)
	privateKey, err := os.ReadFile(path)
	if err != nil {
		warning("read private key [%s] failed: %v", path, err)
		return nil
	}
	signer, err := parsePrivateKey(privateKey)
	if err != nil {
		if e, ok := err.(*ssh.PassphraseMissingError); ok {
			if passphrase := getSecretConfig(param, "Passphrase"); passphrase != "" {
				signer, err = parsePrivateKeyWithPassphrase(privateKey, []byte(passphrase))
			} else {
				return newPassphraseSigner(path, privateKey, e)
			}
		}
		if skErr, ok := err.(*unhandledSecurityKeyError); ok {
			signer, err = parseSecurityKey(path, skErr)
		}
		if err != nil {
			warning("parse private key [%s] failed: %v", path, err)
			return nil
		}
	}
	return newSshSigner(path, nil, signer.PublicKey(), signer)
}

func appendSignerCerts(path string, signer sshSigner, certFiles []string) []sshSigner {
	signers := []sshSigner{signer}

	tryAddCert := func(certPath string) {
		if certPath == "" {
			return
		}
		certPath = resolveHomeDir(certPath)
		if !isFileExist(certPath) {
			return
		}
		certBytes, err := os.ReadFile(certPath)
		if err != nil {
			warning("read public cert [%s] failed: %v", certPath, err)
			return
		}
		certKey, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
		if err != nil {
			warning("parse public cert [%s] failed: %v", certPath, err)
			return
		}
		cert, ok := certKey.(*ssh.Certificate)
		if !ok {
			warning("public cert [%s] can't be converted to ssh.Certificate", certPath)
			return
		}
		certSigner, err := ssh.NewCertSigner(cert, signer)
		if err != nil {
			// Most commonly: cert doesn't match the private key. That's not fatal if
			// multiple CertificateFile entries are configured.
			debug("new cert signer [%s] failed: %v", certPath, err)
			return
		}
		signers = append(signers, newSshSigner(path, nil, certSigner.PublicKey(), certSigner))
	}

	for _, certFile := range certFiles {
		tryAddCert(certFile)
	}

	// OpenSSH's implicit certificate path convention: IdentityFile + "-cert.pub".
	if path != "" {
		tryAddCert(path + "-cert.pub")
	}

	return signers
}

func readSecret(prompt string) (secret []byte, err error) {
	_, _ = os.Stderr.WriteString(prompt)
	defer func() { _, _ = os.Stderr.WriteString("\r\n") }()

	stdin, closer, err := getKeyboardInput()
	if err != nil {
		return nil, err
	}
	defer closer()

	return term.ReadPassword(int(stdin.Fd()))
}

func getPasswordAuthMethod(param *sshParam) ssh.AuthMethod {
	if strings.ToLower(getOptionConfig(param.args, "PasswordAuthentication")) == "no" {
		debug("disable auth method: password authentication")
		return nil
	}

	idx := 0
	rememberPassword := false
	return ssh.RetryableAuthMethod(ssh.PasswordCallback(func() (string, error) {
		idx++
		if idx == 1 {
			password := param.args.Option.get("Password")
			if password == "" {
				password = getSecretConfig(param, "Password")
			}
			if password != "" {
				rememberPassword = true
				debug("trying the password configuration for '%s'", param.args.Destination)
				return password, nil
			}
		} else if idx == 2 && rememberPassword {
			warning("the password configuration for '%s' is incorrect", param.args.Destination)
		}
		secret, err := readSecret(fmt.Sprintf("%s@%s's password: ", param.user, param.host))
		if err != nil {
			return "", err
		}
		return string(secret), nil
	}), 3)
}

func readQuestionAnswerConfig(param *sshParam, idx int, question string) string {
	qhex := hex.EncodeToString([]byte(question))
	debug("the hex code for question '%s' is %s", question, qhex)
	if answer := getSecretConfig(param, qhex); answer != "" {
		return answer
	}

	if secret := getSecretConfig(param, "totp"+qhex); secret != "" {
		if answer := getTotpCode(secret); answer != "" {
			return answer
		}
	}

	if command := getSecretConfig(param, "otp"+qhex); command != "" {
		if answer := getOtpCommandOutput(command, question); answer != "" {
			return answer
		}
	}

	qkey := fmt.Sprintf("QuestionAnswer%d", idx)
	debug("the configuration key for question '%s' is %s", question, qkey)
	if answer := getSecretConfig(param, qkey); answer != "" {
		return answer
	}

	qsecret := fmt.Sprintf("TotpSecret%d", idx)
	debug("the totp secret key for question '%s' is %s", question, qsecret)
	if secret := getSecretConfig(param, qsecret); secret != "" {
		if answer := getTotpCode(secret); answer != "" {
			return answer
		}
	}

	qcmd := fmt.Sprintf("OtpCommand%d", idx)
	debug("the otp command key for question '%s' is %s", question, qcmd)
	if command := getSecretConfig(param, qcmd); command != "" {
		if answer := getOtpCommandOutput(command, question); answer != "" {
			return answer
		}
	}

	return ""
}

func getKeyboardInteractiveAuthMethod(param *sshParam) ssh.AuthMethod {
	if strings.ToLower(getOptionConfig(param.args, "KbdInteractiveAuthentication")) == "no" {
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
					answer := readQuestionAnswerConfig(param, idx, question)
					if answer != "" {
						questionTried[question] = struct{}{}
						answers = append(answers, answer)
						continue
					}
				} else if _, tried := questionTried[question]; tried {
					if _, warned := questionWarned[question]; !warned {
						questionWarned[question] = struct{}{}
						warning("the question answer configuration of '%s' for '%s' is incorrect", question, param.args.Destination)
					}
				}
				secret, err := readSecret(fmt.Sprintf("(%s@%s) %s", param.user, param.host, strings.ReplaceAll(question, "\n", "\r\n")))
				if err != nil {
					return nil, err
				}
				answers = append(answers, string(secret))
			}
			return answers, nil
		}), 3)
}

var getDefaultSigners = func() func() []sshSigner {
	var once sync.Once
	var signers []sshSigner
	return func() []sshSigner {
		once.Do(func() {
			for _, name := range []string{"id_rsa", "id_ecdsa", "id_ecdsa_sk", "id_ed25519", "id_ed25519_sk", "identity"} {
				path := filepath.Join(userHomeDir, ".ssh", name)
				if !isFileExist(path) {
					continue
				}
				if signer := getSigner(&sshParam{args: &sshArgs{Destination: name}}, path); signer != nil {
					signers = append(signers, signer)
				}
			}
		})
		return signers
	}
}()

func getPublicKeysAuthMethod(param *sshParam) ssh.AuthMethod {
	args := param.args
	if v := strings.ToLower(getOptionConfig(args, "PubkeyAuthentication")); v == "no" || v == "false" {
		debug("disable auth method: public key authentication")
		return nil
	}

	var certFiles []string
	for _, certFile := range getAllOptionConfig(args, "CertificateFile") {
		expandedCertFile, err := expandTokens(certFile, param, "%CdhijkLlnpru")
		if err != nil {
			warning("expand CertificateFile [%s] failed: %v", certFile, err)
			continue
		}
		certFiles = append(certFiles, expandedCertFile)
	}

	var addedKeys [][]byte
	var pubKeySigners []ssh.Signer
	addPubKeySigners := func(signers []sshSigner) {
		for _, signer := range signers {
			pubKey := signer.PublicKey()
			keyBytes := pubKey.Marshal()
			if !slices.ContainsFunc(addedKeys, func(e []byte) bool { return bytes.Equal(e, keyBytes) }) {
				if enableDebugLogging {
					debug("will attempt key: %s %s %s", signer.getPath(), shortKeyType(pubKey.Type()), ssh.FingerprintSHA256(pubKey))
				}
				addedKeys = append(addedKeys, keyBytes)
				pubKeySigners = append(pubKeySigners, signer)
			}
		}
	}
	addSignerWithCerts := func(path string, signer sshSigner) {
		addPubKeySigners(appendSignerCerts(path, signer, certFiles))
	}

	identities := args.Identity.values
	for _, identity := range getAllOptionConfig(args, "IdentityFile") {
		expandedIdentity, err := expandTokens(identity, param, "%CdhijkLlnpru")
		if err != nil {
			warning("expand IdentityFile [%s] failed: %v", identity, err)
			continue
		}
		if userConfig.useOpenSSHConfig {
			expandedIdentity = resolveHomeDir(expandedIdentity)
			if !isFileExist(expandedIdentity) {
				debug("IdentityFile [%s] does not exist", expandedIdentity)
				continue
			}
		}
		identities = append(identities, expandedIdentity)
	}

	var agentSigners []ssh.Signer
	if agentClient := getAgentClient(param); agentClient != nil {
		var err error
		agentSigners, err = agentClient.Signers()
		if err != nil {
			warning("get ssh agent signers failed: %v", err)
		}
	}

	if len(identities) > 0 {
	out:
		for _, path := range identities {
			if strings.HasSuffix(path, ".pub") {
				path = resolveHomeDir(path)
				if pubKey := parsePublicKey(path); pubKey != nil {
					for _, agentSigner := range agentSigners {
						if bytes.Equal(pubKey.Marshal(), agentSigner.PublicKey().Marshal()) {
							addSignerWithCerts("", newSshSigner(path+" (agent)", nil, pubKey, agentSigner))
							continue out
						}
					}
				}
			}
			signer := getSigner(param, path)
			if signer == nil {
				continue
			}
			for _, agentSigner := range agentSigners {
				if bytes.Equal(signer.PublicKey().Marshal(), agentSigner.PublicKey().Marshal()) {
					addSignerWithCerts(signer.getPath(), newSshSigner(signer.getPath()+" (agent)", nil, signer.PublicKey(), agentSigner))
					continue out
				}
			}
			addSignerWithCerts(signer.getPath(), signer)
		}
	}

	if strings.ToLower(getOptionConfig(args, "IdentitiesOnly")) != "yes" {
		for _, signer := range agentSigners {
			addSignerWithCerts("", newSshSigner("ssh-agent", nil, signer.PublicKey(), signer))
		}
	}

	if len(identities) == 0 {
		for _, signer := range getDefaultSigners() {
			addSignerWithCerts(signer.getPath(), signer)
		}
	}

	if len(pubKeySigners) == 0 {
		return nil
	}
	return ssh.PublicKeys(pubKeySigners...)
}

func getAuthMethods(param *sshParam) []ssh.AuthMethod {
	var authMethods []ssh.AuthMethod
	if authMethod := getPublicKeysAuthMethod(param); authMethod != nil {
		debug("add auth method: public key authentication")
		authMethods = append(authMethods, authMethod)
	}
	if authMethod := getGSSAPIWithMICAuthMethod(param); authMethod != nil {
		debug("add auth method: gssapi-with-mic authentication")
		authMethods = append(authMethods, authMethod)
	}
	if authMethod := getKeyboardInteractiveAuthMethod(param); authMethod != nil {
		debug("add auth method: keyboard interactive authentication")
		authMethods = append(authMethods, authMethod)
	}
	if authMethod := getPasswordAuthMethod(param); authMethod != nil {
		debug("add auth method: password authentication")
		authMethods = append(authMethods, authMethod)
	}
	return authMethods
}

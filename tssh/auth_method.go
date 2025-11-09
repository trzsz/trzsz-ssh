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
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

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
	for range 3 {
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

func getSignerWithCert(dest string, path string) []*sshSigner {
	signer := getSigner(dest, path)
	if signer == nil {
		return nil
	}
	signers := []*sshSigner{signer}
	certPath := path + "-cert.pub"
	if !isFileExist(certPath) {
		return signers
	}
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		warning("read public cert [%s] failed: %v", certPath, err)
		return signers
	}
	certKey, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		warning("parse public cert [%s] failed: %v", certPath, err)
		return signers
	}
	cert, ok := certKey.(*ssh.Certificate)
	if !ok {
		warning("public cert [%s] can't be converted to ssh.Certificate", certPath)
		return signers
	}
	certSigner, err := ssh.NewCertSigner(cert, signer)
	if err != nil {
		warning("new cert singer [%s] failed: %v", certPath, err)
		return signers
	}
	signers = append(signers, &sshSigner{path: path, pubKey: certSigner.PublicKey(), signer: certSigner})
	return signers
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
				if signer := getSignerWithCert(name, path); len(signer) > 0 {
					signers = append(signers, signer...)
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

	if strings.ToLower(getOptionConfig(args, "IdentitiesOnly")) != "yes" {
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
			if signer := getSignerWithCert(args.Destination, identity); len(signer) > 0 {
				addPubKeySigners(signer)
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
	if authMethod := getGSSAPIWithMICAuthMethod(args, param.host); authMethod != nil {
		debug("add auth method: gssapi-with-mic authentication")
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

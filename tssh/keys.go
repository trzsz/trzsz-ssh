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
	"bufio"
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/trzsz/trzsz-ssh/internal/ssh"
	"golang.org/x/crypto/ssh"
)

type skSigner struct {
	path     string
	keyType  string
	keyBuf   []byte
	pubKey   ssh.PublicKey
	keyFlags uint8
}

func (s *skSigner) PublicKey() ssh.PublicKey {
	return s.pubKey
}

type skSignRequest struct {
	Version   uint8
	ReqType   uint32
	LogStderr uint8
	LogLevel  uint32
	Key       []byte
	Provider  string
	Data      []byte
	Algorithm string
	Compat    uint32
	Pin       string
}

type skSignSignature struct {
	Signature []byte
	Rest      []byte `ssh:"rest"`
}

type skSignResponse struct {
	Version  uint8
	RespType uint32
	Rest     []byte `ssh:"rest"`
}

func writeMessage(w io.Writer, payload []byte) error {
	if err := binary.Write(w, binary.BigEndian, uint32(len(payload))); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readMessage(r io.Reader) ([]byte, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	return buf, nil
}

func (s *skSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.SignWithAlgorithm(rand, data, "")
}

func (s *skSigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	logLevel := uint32(2) // SYSLOG_LEVEL_ERROR = 2
	if enableDebugLogging {
		logLevel = uint32(7) // SYSLOG_LEVEL_DEBUG3 = 7
	}
	skProvider := os.Getenv("SSH_SK_PROVIDER")
	if skProvider == "" {
		skProvider = "internal"
	}

	skHelperPath := os.Getenv("SSH_SK_HELPER")
	if skHelperPath == "" {
		skHelperPath = kDefaultSshSkHelperPath
	}
	if !isFileExist(skHelperPath) {
		return nil, fmt.Errorf("ssh-sk-helper not found: %s", skHelperPath)
	}

	keyBuf := make([]byte, 4+len(s.keyType)+len(s.keyBuf))
	binary.BigEndian.PutUint32(keyBuf, uint32(len(s.keyType)))
	copy(keyBuf[4:], s.keyType)
	copy(keyBuf[4+len(s.keyType):], s.keyBuf)

	userPresenceRequired := s.keyFlags&1 != 0 // SSH_SK_USER_PRESENCE_REQD = 1

	for i := range 4 {
		debug("starting ssh-sk-helper: %s", skHelperPath)

		pin := ""
		if i > 0 {
			secret, err := readSecret(fmt.Sprintf("Enter PIN for %s key %s: ", shortKeyType(s.keyType), s.path))
			if err != nil {
				return nil, fmt.Errorf("read pin failed: %v", err)
			}
			pin = string(secret)
		}

		req := skSignRequest{
			Version:   5, // SSH_SK_HELPER_VERSION = 5
			ReqType:   1, // SSH_SK_HELPER_SIGN = 1
			LogStderr: 1, // on_stderr != 0
			LogLevel:  logLevel,
			Key:       keyBuf,
			Provider:  skProvider,
			Algorithm: algorithm,
			Data:      data,
			Pin:       pin,
		}

		if userPresenceRequired {
			fmt.Fprintf(os.Stderr, "\033[0;36mConfirm user presence for key %s %s\033[0m",
				shortKeyType(s.keyType), ssh.FingerprintSHA256(s.pubKey))
		}

		cmd := exec.Command(skHelperPath)
		if enableDebugLogging {
			cmd.Args = append(cmd.Args, "-vvv")
		}

		var stdin bytes.Buffer
		var stdout bytes.Buffer
		cmd.Stdin = &stdin
		cmd.Stdout = &stdout

		if enableDebugLogging {
			stderr, err := cmd.StderrPipe()
			if err != nil {
				return nil, fmt.Errorf("stderr pipe failed: %v", err)
			}
			go func() {
				defer func() { _ = stderr.Close() }()
				scanner := bufio.NewScanner(stderr)
				for scanner.Scan() {
					debug("%s", scanner.Text())
				}
			}()
		} else {
			cmd.Stderr = os.Stderr
		}

		if err := writeMessage(&stdin, ssh.Marshal(req)); err != nil {
			return nil, fmt.Errorf("write request failed: %v", err)
		}

		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("run %s failed: %v", skHelperPath, err)
		}

		if userPresenceRequired {
			fmt.Fprintf(os.Stderr, "\r\033[K")
		}

		respPayload, err := readMessage(&stdout)
		if err != nil {
			return nil, fmt.Errorf("read response failed: %v", err)
		}

		var resp skSignResponse
		if err := ssh.Unmarshal(respPayload, &resp); err != nil {
			return nil, fmt.Errorf("unmarshal response failed: %v", err)
		}
		if resp.Version != 5 { // SSH_SK_HELPER_VERSION = 5
			return nil, fmt.Errorf("unexpected ssh-sk-helper version: %d", resp.Version)
		}
		switch resp.RespType {
		case 0: // SSH_SK_HELPER_ERROR
			code := binary.BigEndian.Uint32(resp.Rest)
			if code == 43 { // SSH_ERR_KEY_WRONG_PASSPHRASE = -43
				continue
			}
			return nil, fmt.Errorf("ssh-sk-helper error with code: %d", code)
		case 1: // SSH_SK_HELPER_SIGN = 1
			var skSign skSignSignature
			if err := ssh.Unmarshal(resp.Rest, &skSign); err != nil {
				return nil, fmt.Errorf("unmarshal sk_signature failed: %v", err)
			}
			var sign ssh.Signature
			if err := ssh.Unmarshal(skSign.Signature, &sign); err != nil {
				return nil, fmt.Errorf("unmarshal signature failed: %v", err)
			}
			return &sign, nil
		default:
			return nil, fmt.Errorf("unexpected ssh-sk-helper response type: %d", resp.RespType)
		}
	}

	return nil, fmt.Errorf("PIN incorrect")
}

type skECDSAPrivateKey struct {
	Curve string
	Pub   []byte
	App   string
	Flags uint8
	Rest  []byte `ssh:"rest"`
}

type skEd25519PrivateKey struct {
	PubKey []byte
	App    string
	Flags  uint8
	Rest   []byte `ssh:"rest"`
}

func parseSecurityKey(path string, skErr *unhandledSecurityKeyError) (*skSigner, error) {
	pubKey, err := ssh.ParsePublicKey(skErr.PubKey)
	if err != nil {
		return nil, fmt.Errorf("parse public key failed: %v", err)
	}

	var keyFlags uint8
	switch skErr.KeyType {
	case ssh.KeyAlgoSKED25519:
		var pk skEd25519PrivateKey
		if err := ssh.Unmarshal(skErr.Rest, &pk); err != nil {
			return nil, err
		}
		keyFlags = pk.Flags
	case ssh.KeyAlgoSKECDSA256:
		var pk skECDSAPrivateKey
		if err := ssh.Unmarshal(skErr.Rest, &pk); err != nil {
			return nil, err
		}
		keyFlags = pk.Flags
	default:
		return nil, fmt.Errorf("ssh: unhandled key type %q", skErr.KeyType)
	}

	return &skSigner{path, skErr.KeyType, skErr.Rest, pubKey, keyFlags}, nil
}

func shortKeyType(keyType string) string {
	switch keyType {
	case ssh.KeyAlgoRSA, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512:
		return "RSA"
	case ssh.CertAlgoRSAv01, ssh.CertAlgoRSASHA256v01, ssh.CertAlgoRSASHA512v01:
		return "RSA-CERT"
	case ssh.KeyAlgoED25519:
		return "ED25519"
	case ssh.CertAlgoED25519v01:
		return "ED25519-CERT"
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		return "ECDSA"
	case ssh.CertAlgoECDSA256v01, ssh.CertAlgoECDSA384v01, ssh.CertAlgoECDSA521v01:
		return "ECDSA-CERT"
	case ssh.KeyAlgoSKECDSA256:
		return "ECDSA-SK"
	case ssh.CertAlgoSKECDSA256v01:
		return "ECDSA-SK-CERT"
	case ssh.KeyAlgoSKED25519:
		return "ED25519-SK"
	case ssh.CertAlgoSKED25519v01:
		return "ED25519-SK-CERT"
	default:
		return keyType
	}
}

// ==================== The following code is adapted from golang.org/x/crypto/ssh ====================

type unhandledSecurityKeyError struct {
	KeyType string
	PubKey  []byte
	Rest    []byte
}

func (e *unhandledSecurityKeyError) Error() string {
	return fmt.Sprintf("ssh: unhandled security key type %q", e.KeyType)
}

const kUnhandledKeyTypeError = "ssh: unhandled key type"

// encryptedBlock tells whether a private key is
// encrypted by examining its Proc-Type header
// for a mention of ENCRYPTED
// according to RFC 1421 Section 4.6.1.1.
func encryptedBlock(block *pem.Block) bool {
	return strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED")
}

// parsePrivateKey returns a Signer from a PEM encoded private key. It supports
// the same keys as ParseRawPrivateKey. If the private key is encrypted, it
// will return a PassphraseMissingError.
func parsePrivateKey(pemBytes []byte) (ssh.Signer, error) {
	signer, err := ssh.ParsePrivateKey(pemBytes)

	if err != nil && err.Error() == kUnhandledKeyTypeError {
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			return nil, errors.New("ssh: no key found")
		}

		if encryptedBlock(block) {
			return nil, &ssh.PassphraseMissingError{}
		}

		if block.Type == "OPENSSH PRIVATE KEY" {
			_, err = parseOpenSSHPrivateKey(block.Bytes, unencryptedOpenSSHKey)
		}
	}

	return signer, err
}

// parsePrivateKeyWithPassphrase returns a Signer from a PEM encoded private
// key and passphrase. It supports the same keys as
// ParseRawPrivateKeyWithPassphrase.
func parsePrivateKeyWithPassphrase(pemBytes, passphrase []byte) (ssh.Signer, error) {
	signer, err := ssh.ParsePrivateKeyWithPassphrase(pemBytes, passphrase)

	if err != nil && err.Error() == kUnhandledKeyTypeError {
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			return nil, errors.New("ssh: no key found")
		}
		if block.Type == "OPENSSH PRIVATE KEY" {
			_, err = parseOpenSSHPrivateKey(block.Bytes, passphraseProtectedOpenSSHKey(passphrase))
		}
	}

	return signer, err
}

func unencryptedOpenSSHKey(cipherName, kdfName, kdfOpts string, privKeyBlock []byte) ([]byte, error) {
	if kdfName != "none" || cipherName != "none" {
		return nil, &ssh.PassphraseMissingError{}
	}
	if kdfOpts != "" {
		return nil, errors.New("ssh: invalid openssh private key")
	}
	return privKeyBlock, nil
}

func passphraseProtectedOpenSSHKey(passphrase []byte) openSSHDecryptFunc {
	return func(cipherName, kdfName, kdfOpts string, privKeyBlock []byte) ([]byte, error) {
		if kdfName == "none" || cipherName == "none" {
			return nil, errors.New("ssh: key is not password protected")
		}
		if kdfName != "bcrypt" {
			return nil, fmt.Errorf("ssh: unknown KDF %q, only supports %q", kdfName, "bcrypt")
		}

		var opts struct {
			Salt   string
			Rounds uint32
		}
		if err := ssh.Unmarshal([]byte(kdfOpts), &opts); err != nil {
			return nil, err
		}

		k, err := bcrypt_pbkdf.Key(passphrase, []byte(opts.Salt), int(opts.Rounds), 32+16)
		if err != nil {
			return nil, err
		}
		key, iv := k[:32], k[32:]

		c, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		switch cipherName {
		case "aes256-ctr":
			ctr := cipher.NewCTR(c, iv)
			ctr.XORKeyStream(privKeyBlock, privKeyBlock)
		case "aes256-cbc":
			if len(privKeyBlock)%c.BlockSize() != 0 {
				return nil, fmt.Errorf("ssh: invalid encrypted private key length, not a multiple of the block size")
			}
			cbc := cipher.NewCBCDecrypter(c, iv)
			cbc.CryptBlocks(privKeyBlock, privKeyBlock)
		default:
			return nil, fmt.Errorf("ssh: unknown cipher %q, only supports %q or %q", cipherName, "aes256-ctr", "aes256-cbc")
		}

		return privKeyBlock, nil
	}
}

const privateKeyAuthMagic = "openssh-key-v1\x00"

type openSSHDecryptFunc func(CipherName, KdfName, KdfOpts string, PrivKeyBlock []byte) ([]byte, error)

type openSSHEncryptedPrivateKey struct {
	CipherName   string
	KdfName      string
	KdfOpts      string
	NumKeys      uint32
	PubKey       []byte
	PrivKeyBlock []byte
	Rest         []byte `ssh:"rest"`
}

type openSSHPrivateKey struct {
	Check1  uint32
	Check2  uint32
	Keytype string
	Rest    []byte `ssh:"rest"`
}

// parseOpenSSHPrivateKey parses an OpenSSH private key, using the decrypt
// function to unwrap the encrypted portion. unencryptedOpenSSHKey can be used
// as the decrypt function to parse an unencrypted private key. See
// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key.
func parseOpenSSHPrivateKey(key []byte, decrypt openSSHDecryptFunc) (crypto.PrivateKey, error) {
	if len(key) < len(privateKeyAuthMagic) || string(key[:len(privateKeyAuthMagic)]) != privateKeyAuthMagic {
		return nil, errors.New("ssh: invalid openssh private key format")
	}
	remaining := key[len(privateKeyAuthMagic):]

	var w openSSHEncryptedPrivateKey
	if err := ssh.Unmarshal(remaining, &w); err != nil {
		return nil, err
	}
	if w.NumKeys != 1 {
		// We only support single key files, and so does OpenSSH.
		// https://github.com/openssh/openssh-portable/blob/4103a3ec7/sshkey.c#L4171
		return nil, errors.New("ssh: multi-key files are not supported")
	}

	privKeyBlock, err := decrypt(w.CipherName, w.KdfName, w.KdfOpts, w.PrivKeyBlock)
	if err != nil {
		if err, ok := err.(*ssh.PassphraseMissingError); ok {
			pub, errPub := ssh.ParsePublicKey(w.PubKey)
			if errPub != nil {
				return nil, fmt.Errorf("ssh: failed to parse embedded public key: %v", errPub)
			}
			err.PublicKey = pub
		}
		return nil, err
	}

	var pk1 openSSHPrivateKey
	if err := ssh.Unmarshal(privKeyBlock, &pk1); err != nil || pk1.Check1 != pk1.Check2 {
		if w.CipherName != "none" {
			return nil, x509.IncorrectPasswordError
		}
		return nil, errors.New("ssh: malformed OpenSSH key")
	}

	switch pk1.Keytype {
	case ssh.KeyAlgoSKED25519, ssh.KeyAlgoSKECDSA256:
		return nil, &unhandledSecurityKeyError{pk1.Keytype, w.PubKey, pk1.Rest}
	default:
		return nil, errors.New("ssh: unhandled key type")
	}
}

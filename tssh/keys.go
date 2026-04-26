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
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/trzsz/trzsz-ssh/internal/ssh"
	"golang.org/x/crypto/ssh"
)

type skSigner struct {
	path   string
	pubKey ssh.PublicKey
	keyBuf []byte
	flags  uint8
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

	for i := range 4 {
		debug("starting ssh-sk-helper: %s", skHelperPath)

		pin := ""
		if i > 0 {
			secret, err := readSecret(fmt.Sprintf("Enter PIN for %s key %s: ", shortKeyType(s.pubKey.Type()), s.path))
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
			Key:       s.keyBuf,
			Provider:  skProvider,
			Algorithm: algorithm,
			Data:      data,
			Pin:       pin,
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

		if s.flags&1 != 0 { // SSH_SK_USER_PRESENCE_REQD = 1
			if err := s.runWithPrompt(cmd); err != nil {
				return nil, err
			}
		} else {
			if err := cmd.Run(); err != nil {
				return nil, fmt.Errorf("run %s failed: %v", skHelperPath, err)
			}
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
			if code == 60 { // SSH_ERR_DEVICE_NOT_FOUND = -60
				return nil, fmt.Errorf("device not found")
			}
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

func (s *skSigner) runWithPrompt(cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s failed: %v", cmd.Path, err)
	}

	fmt.Fprintf(os.Stderr, "%s%s", ansi.HideCursor, ansi.ResetModeAutoWrap)
	defer fmt.Fprintf(os.Stderr, "\r%s%s%s", ansi.EraseLineRight, ansi.SetModeAutoWrap, ansi.ShowCursor)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer func() { signal.Stop(sigChan); close(sigChan) }()

	doneChan := make(chan error, 1)
	go func() {
		defer close(doneChan)
		if err := cmd.Wait(); err != nil {
			doneChan <- fmt.Errorf("wait %s failed: %v", cmd.Path, err)
			return
		}
		doneChan <- nil
	}()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	show := true
	msg := fmt.Sprintf("Confirm user presence for key %s '%s' %s",
		shortKeyType(s.pubKey.Type()), s.path, ssh.FingerprintSHA256(s.pubKey))
	shownMsg := fmt.Sprintf("\r\033[1;36m[ ACTION REQUIRED ] %s\033[0m", msg)
	blankMsg := fmt.Sprintf("\r\033[1;36m[                 ] %s\033[0m", msg)

	for {
		select {
		case sig := <-sigChan:
			_ = cmd.Process.Kill()
			if sig == os.Interrupt || sig.String() == "interrupt" {
				return fmt.Errorf("interrupted by user")
			}
			return fmt.Errorf("terminated by signal: %v", sig)
		case err := <-doneChan:
			return err
		case <-ticker.C:
			if show {
				fmt.Fprint(os.Stderr, shownMsg)
			} else {
				fmt.Fprint(os.Stderr, blankMsg)
			}
			show = !show
		}
	}
}

func parseSecurityKey(path string, skErr *unsupportedSecurityKeyError) (*skSigner, error) {
	return &skSigner{
		path:   path,
		pubKey: skErr.PublicKey,
		keyBuf: skErr.Raw,
		flags:  skErr.Flags,
	}, nil
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

// ==================== The following code is adapted from https://go.dev/cl/768800 ====================

// unsupportedSecurityKeyError is returned when attempting to parse an
// OpenSSH private key of a security key (sk-*) type. Security key private
// keys require external hardware (FIDO/U2F) for signing operations and
// are not directly supported by this package.
//
// The error exposes the parsed public key along with the FIDO-specific
// metadata needed to perform signing via an external helper such as
// ssh-sk-helper.
//
// See openssh/PROTOCOL.u2f 'SSH U2F Signatures' for details.
type unsupportedSecurityKeyError struct {
	// PublicKey is the parsed and validated public key from the key file.
	PublicKey ssh.PublicKey

	// Flags contains the FIDO key flags. Bit 0x01 indicates that
	// user presence (touch) is required for each signature.
	Flags uint8

	// Raw contains the full private key in OpenSSH wire encoding,
	// starting from the key type string. It can be passed directly
	// to ssh-sk-helper or similar external signing helpers without
	// any reassembly. Trailing comment and padding bytes may be
	// present after the SK-specific fields.
	Raw []byte
}

func (e *unsupportedSecurityKeyError) Error() string {
	// Defensive nil check: parseOpenSSHPrivateKey always sets PublicKey,
	// but guard against manually constructed values (tests, mocks).
	if e.PublicKey == nil {
		return "ssh: unsupported security key"
	}
	return fmt.Sprintf("ssh: unsupported security key type %q", e.PublicKey.Type())
}

// skFlagsFromRest extracts the FIDO flags byte from the type-specific
// private key fields. The flags are located after the public key material,
// which varies by key type:
//   - sk-ecdsa: curve(string) + Q(string) + application(string) + flags
//   - sk-ed25519: pubkey(string) + application(string) + flags
func skFlagsFromRest(keyType string, rest []byte) (uint8, error) {
	// Number of public key fields before the application string.
	var skipCount int
	switch keyType {
	case ssh.KeyAlgoSKECDSA256:
		skipCount = 2 // curve + ec_point
	case ssh.KeyAlgoSKED25519:
		skipCount = 1 // pubkey
	default:
		return 0, fmt.Errorf("ssh: not a security key type: %s", keyType)
	}

	buf := rest
	// Skip the public key material fields and the application string.
	for i := 0; i < skipCount+1; i++ {
		if len(buf) < 4 {
			return 0, errors.New("ssh: truncated security key data")
		}
		fieldLen := binary.BigEndian.Uint32(buf[:4])
		if uint32(len(buf)-4) < fieldLen {
			return 0, errors.New("ssh: truncated security key data")
		}
		buf = buf[4+fieldLen:]
	}
	// buf[0] is the flags byte.
	if len(buf) < 1 {
		return 0, errors.New("ssh: truncated security key data")
	}
	return buf[0], nil
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
		pubKey, err := ssh.ParsePublicKey(w.PubKey)
		if err != nil {
			return nil, fmt.Errorf("ssh: failed to parse security key public key: %v", err)
		}
		flags, err := skFlagsFromRest(pk1.Keytype, pk1.Rest)
		if err != nil {
			return nil, err
		}
		return nil, &unsupportedSecurityKeyError{
			PublicKey: pubKey,
			Raw:       privKeyBlock[8:],
			Flags:     flags,
		}
	default:
		return nil, errors.New("ssh: unhandled key type")
	}
}

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
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"

	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/ssh"
)

var errNotSecurityKeyPrivateKey = errors.New("ssh: not an OpenSSH security key private key")

const privateKeyAuthMagic = "openssh-key-v1\x00"

type openSSHDecryptFunc func(cipherName, kdfName, kdfOpts string, privKeyBlock []byte) ([]byte, error)

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

type openSSHSKEd25519PrivateKey struct {
	Pub         []byte
	Application string
	Flags       uint8
	KeyHandle   []byte
	Reserved    []byte
	Comment     string
	Pad         []byte `ssh:"rest"`
}

type openSSHSKECDSAPrivateKey struct {
	Curve       string
	Pub         []byte
	Application string
	Flags       uint8
	KeyHandle   []byte
	Reserved    []byte
	Comment     string
	Pad         []byte `ssh:"rest"`
}

type securityKeyPrivateKey struct {
	publicKey   ssh.PublicKey
	application string
	flags       byte
	keyHandle   []byte
	reserved    []byte
}

type securityKeySignatureRest struct {
	Flags   byte
	Counter uint32
}

type lazySecurityKeySigner struct {
	path       string
	priKey     []byte
	pubKey     ssh.PublicKey
	passphrase []byte
	provider   securityKeyProvider
	signer     ssh.Signer
}

type securityKeySigner struct {
	path        string
	publicKey   ssh.PublicKey
	application string
	flags       byte
	keyHandle   []byte
	reserved    []byte
	provider    securityKeyProvider
}

func isSecurityKeyPublicKey(pubKey ssh.PublicKey) bool {
	if pubKey == nil {
		return false
	}
	switch pubKey.Type() {
	case ssh.KeyAlgoSKED25519, ssh.KeyAlgoSKECDSA256:
		return true
	default:
		return false
	}
}

func parseOpenSSHEncryptedPrivateKey(pemBytes []byte) (*openSSHEncryptedPrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errNotSecurityKeyPrivateKey
	}
	if block.Type != "OPENSSH PRIVATE KEY" {
		return nil, errNotSecurityKeyPrivateKey
	}
	if len(block.Bytes) < len(privateKeyAuthMagic) || string(block.Bytes[:len(privateKeyAuthMagic)]) != privateKeyAuthMagic {
		return nil, errNotSecurityKeyPrivateKey
	}

	var w openSSHEncryptedPrivateKey
	if err := ssh.Unmarshal(block.Bytes[len(privateKeyAuthMagic):], &w); err != nil {
		return nil, err
	}
	if w.NumKeys != 1 {
		return nil, errors.New("ssh: multi-key files are not supported")
	}
	return &w, nil
}

// parseSecurityKeyPrivateKey adapts the OpenSSH private-key parsing flow from
// golang.org/x/crypto/ssh/keys.go because upstream does not expose the needed
// helpers and does not yet support OpenSSH SK private keys.
func parseSecurityKeyPrivateKey(pemBytes, passphrase []byte) (*securityKeyPrivateKey, error) {
	w, err := parseOpenSSHEncryptedPrivateKey(pemBytes)
	if err != nil {
		return nil, err
	}
	pubKey, pubErr := ssh.ParsePublicKey(w.PubKey)

	decrypt := unencryptedOpenSSHKey
	if passphrase != nil {
		decrypt = passphraseProtectedOpenSSHKey(passphrase)
	}
	privKeyBlock, err := decrypt(w.CipherName, w.KdfName, w.KdfOpts, w.PrivKeyBlock)
	if err != nil {
		if missing, ok := err.(*ssh.PassphraseMissingError); ok && missing.PublicKey == nil && pubErr == nil {
			missing.PublicKey = pubKey
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

	if pubErr != nil {
		return nil, fmt.Errorf("ssh: failed to parse embedded public key: %v", pubErr)
	}

	switch pk1.Keytype {
	case ssh.KeyAlgoSKED25519:
		var key openSSHSKEd25519PrivateKey
		if err := ssh.Unmarshal(pk1.Rest, &key); err != nil {
			return nil, err
		}
		if err := checkOpenSSHKeyPadding(key.Pad); err != nil {
			return nil, err
		}
		return &securityKeyPrivateKey{
			publicKey:   pubKey,
			application: key.Application,
			flags:       key.Flags,
			keyHandle:   key.KeyHandle,
			reserved:    key.Reserved,
		}, nil
	case ssh.KeyAlgoSKECDSA256:
		var key openSSHSKECDSAPrivateKey
		if err := ssh.Unmarshal(pk1.Rest, &key); err != nil {
			return nil, err
		}
		if err := checkOpenSSHKeyPadding(key.Pad); err != nil {
			return nil, err
		}
		return &securityKeyPrivateKey{
			publicKey:   pubKey,
			application: key.Application,
			flags:       key.Flags,
			keyHandle:   key.KeyHandle,
			reserved:    key.Reserved,
		}, nil
	default:
		return nil, errNotSecurityKeyPrivateKey
	}
}

func newSecurityKeySigner(path string, priKey []byte, pubKey ssh.PublicKey, passphrase []byte) ssh.Signer {
	return newSecurityKeySignerWithProvider(path, priKey, pubKey, passphrase, newSecurityKeyProvider())
}

func newSecurityKeySignerWithProvider(path string, priKey []byte, pubKey ssh.PublicKey, passphrase []byte,
	provider securityKeyProvider,
) ssh.Signer {
	return &lazySecurityKeySigner{
		path:       path,
		priKey:     priKey,
		pubKey:     pubKey,
		passphrase: passphrase,
		provider:   provider,
	}
}

func (s *lazySecurityKeySigner) getPath() string {
	return s.path
}

func (s *lazySecurityKeySigner) PublicKey() ssh.PublicKey {
	return s.pubKey
}

func (s *lazySecurityKeySigner) initSigner() error {
	if s.signer != nil {
		return nil
	}

	buildSigner := func(passphrase []byte) error {
		key, err := parseSecurityKeyPrivateKey(s.priKey, passphrase)
		if err != nil {
			return err
		}
		s.signer = &securityKeySigner{
			path:        s.path,
			publicKey:   s.pubKey,
			application: key.application,
			flags:       key.flags,
			keyHandle:   key.keyHandle,
			reserved:    key.reserved,
			provider:    s.provider,
		}
		return nil
	}

	if err := buildSigner(nil); err == nil {
		return nil
	} else if !isSecurityKeyPassphraseError(err) {
		return err
	}

	if len(s.passphrase) > 0 {
		if err := buildSigner(s.passphrase); err == nil {
			return nil
		} else if err != x509.IncorrectPasswordError && !isSecurityKeyPassphraseError(err) {
			return err
		}
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
		if err := buildSigner(secret); err == nil {
			return nil
		} else if err != x509.IncorrectPasswordError && !isSecurityKeyPassphraseError(err) {
			return err
		}
	}
	return fmt.Errorf("passphrase incorrect")
}

func (s *lazySecurityKeySigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	if err := s.initSigner(); err != nil {
		return nil, err
	}
	return s.signer.Sign(rand, data)
}

func (s *securityKeySigner) getPath() string {
	return s.path
}

func (s *securityKeySigner) PublicKey() ssh.PublicKey {
	return s.publicKey
}

func (s *securityKeySigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	if enableDebugLogging {
		debug("sign with key: %s", ssh.FingerprintSHA256(s.publicKey))
	}
	result, err := s.provider.Sign(s.publicKey.Type(), s.application, s.flags, s.keyHandle, data)
	if err != nil {
		warning("sign with [%s] failed: %v", ssh.FingerprintSHA256(s.publicKey), err)
		return nil, err
	}
	blob, err := marshalSecurityKeySignature(s.publicKey.Type(), result.blob)
	if err != nil {
		return nil, err
	}
	return &ssh.Signature{
		Format: s.publicKey.Type(),
		Blob:   blob,
		Rest:   ssh.Marshal(securityKeySignatureRest{Flags: result.flags, Counter: result.counter}),
	}, nil
}

func marshalSecurityKeySignature(algorithm string, sig []byte) ([]byte, error) {
	switch algorithm {
	case ssh.KeyAlgoSKED25519:
		return sig, nil
	case ssh.KeyAlgoSKECDSA256:
		var ecdsaSig struct {
			R, S *big.Int
		}
		if _, err := asn1.Unmarshal(sig, &ecdsaSig); err != nil {
			return nil, err
		}
		if ecdsaSig.R == nil || ecdsaSig.S == nil {
			return nil, errors.New("invalid security key ecdsa signature")
		}
		return ssh.Marshal(ecdsaSig), nil
	}
	return nil, fmt.Errorf("unsupported security key algorithm: %s", algorithm)
}

func getIdentityPublicKey(path string) (ssh.PublicKey, error) {
	path = resolveHomeDir(path)
	if pubData, err := os.ReadFile(path + ".pub"); err == nil {
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pubData)
		if err == nil {
			return pubKey, nil
		}
	}

	privateKey, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if signer, err := ssh.ParsePrivateKey(privateKey); err == nil {
		return signer.PublicKey(), nil
	} else if missing, ok := err.(*ssh.PassphraseMissingError); ok && missing.PublicKey != nil {
		return missing.PublicKey, nil
	}
	if key, err := parseSecurityKeyPrivateKey(privateKey, nil); err == nil {
		return key.publicKey, nil
	} else if missing, ok := err.(*ssh.PassphraseMissingError); ok && missing.PublicKey != nil {
		return missing.PublicKey, nil
	} else if !errors.Is(err, errNotSecurityKeyPrivateKey) {
		return nil, err
	}
	return nil, fmt.Errorf("parse public key [%s] failed", path)
}

func findIdentityAgentSigner(path string, signers []ssh.Signer) (ssh.Signer, ssh.PublicKey) {
	if len(signers) == 0 {
		return nil, nil
	}
	pubKey, err := getIdentityPublicKey(path)
	if err != nil {
		return nil, nil
	}
	fingerprint := ssh.FingerprintSHA256(pubKey)
	for _, signer := range signers {
		if ssh.FingerprintSHA256(signer.PublicKey()) == fingerprint {
			return newSshSigner(path, nil, pubKey, signer), pubKey
		}
	}
	return nil, pubKey
}

func isSecurityKeyPassphraseError(err error) bool {
	var missing *ssh.PassphraseMissingError
	return errors.As(err, &missing)
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

		keyMaterial, err := bcryptPBKDFKey(passphrase, []byte(opts.Salt), int(opts.Rounds), 32+16)
		if err != nil {
			return nil, err
		}
		key, iv := keyMaterial[:32], keyMaterial[32:]

		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		switch cipherName {
		case "aes256-ctr":
			cipher.NewCTR(block, iv).XORKeyStream(privKeyBlock, privKeyBlock)
		case "aes256-cbc":
			if len(privKeyBlock)%block.BlockSize() != 0 {
				return nil, fmt.Errorf("ssh: invalid encrypted private key length, not a multiple of the block size")
			}
			cipher.NewCBCDecrypter(block, iv).CryptBlocks(privKeyBlock, privKeyBlock)
		default:
			return nil, fmt.Errorf("ssh: unknown cipher %q, only supports %q or %q", cipherName, "aes256-ctr", "aes256-cbc")
		}
		return privKeyBlock, nil
	}
}

func checkOpenSSHKeyPadding(pad []byte) error {
	for i, b := range pad {
		if int(b) != i+1 {
			return errors.New("ssh: padding not as expected")
		}
	}
	return nil
}

const bcryptPBKDFBlockSize = 32

// bcryptPBKDFKey is adapted from golang.org/x/crypto/ssh/internal/bcrypt_pbkdf
// because that package is internal and cannot be imported here.
func bcryptPBKDFKey(password, salt []byte, rounds, keyLen int) ([]byte, error) {
	if rounds < 1 {
		return nil, errors.New("bcrypt_pbkdf: number of rounds is too small")
	}
	if len(password) == 0 {
		return nil, errors.New("bcrypt_pbkdf: empty password")
	}
	if len(salt) == 0 || len(salt) > 1<<20 {
		return nil, errors.New("bcrypt_pbkdf: bad salt length")
	}
	if keyLen > 1024 {
		return nil, errors.New("bcrypt_pbkdf: keyLen is too large")
	}

	numBlocks := (keyLen + bcryptPBKDFBlockSize - 1) / bcryptPBKDFBlockSize
	key := make([]byte, numBlocks*bcryptPBKDFBlockSize)

	h := sha512.New()
	h.Write(password)
	shapePass := h.Sum(nil)

	shapeSalt := make([]byte, 0, sha512.Size)
	counter := make([]byte, 4)
	tmp := make([]byte, bcryptPBKDFBlockSize)
	for block := 1; block <= numBlocks; block++ {
		h.Reset()
		h.Write(salt)
		counter[0] = byte(block >> 24)
		counter[1] = byte(block >> 16)
		counter[2] = byte(block >> 8)
		counter[3] = byte(block)
		h.Write(counter)
		bcryptHash(tmp, shapePass, h.Sum(shapeSalt))

		out := make([]byte, bcryptPBKDFBlockSize)
		copy(out, tmp)
		for i := 2; i <= rounds; i++ {
			h.Reset()
			h.Write(tmp)
			bcryptHash(tmp, shapePass, h.Sum(shapeSalt))
			for j := range out {
				out[j] ^= tmp[j]
			}
		}

		for i, v := range out {
			key[i*numBlocks+(block-1)] = v
		}
	}
	return key[:keyLen], nil
}

var bcryptPBKDFMagic = []byte("OxychromaticBlowfishSwatDynamite")

func bcryptHash(out, shapePass, shapeSalt []byte) {
	c, err := blowfish.NewSaltedCipher(shapePass, shapeSalt)
	if err != nil {
		panic(err)
	}
	for range 64 {
		blowfish.ExpandKey(shapeSalt, c)
		blowfish.ExpandKey(shapePass, c)
	}
	copy(out, bcryptPBKDFMagic)
	for i := 0; i < bcryptPBKDFBlockSize; i += 8 {
		for range 64 {
			c.Encrypt(out[i:i+8], out[i:i+8])
		}
	}
	for i := 0; i < bcryptPBKDFBlockSize; i += 4 {
		out[i+3], out[i+2], out[i+1], out[i] = out[i], out[i+1], out[i+2], out[i+3]
	}
}

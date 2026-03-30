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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type fakeSecurityKeyProvider func(algorithm, application string, flags byte, keyHandle, data []byte) (*securityKeySignResult, error)

func (f fakeSecurityKeyProvider) Sign(algorithm, application string, flags byte, keyHandle, data []byte) (*securityKeySignResult, error) {
	return f(algorithm, application, flags, keyHandle, data)
}

type staticSigner struct {
	pubKey ssh.PublicKey
}

func (s staticSigner) PublicKey() ssh.PublicKey {
	return s.pubKey
}

func (s staticSigner) Sign(io.Reader, []byte) (*ssh.Signature, error) {
	return nil, nil
}

type fakeExtendedAgent struct {
	signers []ssh.Signer
}

func (a fakeExtendedAgent) List() ([]*agent.Key, error) {
	return nil, nil
}

func (a fakeExtendedAgent) Sign(ssh.PublicKey, []byte) (*ssh.Signature, error) {
	return nil, errors.New("not implemented")
}

func (a fakeExtendedAgent) Add(agent.AddedKey) error {
	return errors.New("not implemented")
}

func (a fakeExtendedAgent) Remove(ssh.PublicKey) error {
	return errors.New("not implemented")
}

func (a fakeExtendedAgent) RemoveAll() error {
	return nil
}

func (a fakeExtendedAgent) Lock([]byte) error {
	return nil
}

func (a fakeExtendedAgent) Unlock([]byte) error {
	return nil
}

func (a fakeExtendedAgent) Signers() ([]ssh.Signer, error) {
	return a.signers, nil
}

func (a fakeExtendedAgent) SignWithFlags(ssh.PublicKey, []byte, agent.SignatureFlags) (*ssh.Signature, error) {
	return nil, errors.New("not implemented")
}

func (a fakeExtendedAgent) Extension(string, []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

func TestParseSecurityKeyPrivateKey(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	edPubKey := mustParseSKEd25519PublicKey(t, edPub, "ssh:")
	edPEM := marshalSKEd25519PrivateKey(t, edPub, "ssh:", sshSkUserPresenceRequired|sshSkUserVerificationRequired, []byte("ed-handle"))

	edKey, err := parseSecurityKeyPrivateKey(edPEM, nil)
	require.NoError(t, err)
	assert.Equal(t, ssh.KeyAlgoSKED25519, edKey.publicKey.Type())
	assert.Equal(t, "ssh:", edKey.application)
	assert.Equal(t, byte(sshSkUserPresenceRequired|sshSkUserVerificationRequired), edKey.flags)
	assert.Equal(t, []byte("ed-handle"), edKey.keyHandle)
	assert.Equal(t, ssh.FingerprintSHA256(edPubKey), ssh.FingerprintSHA256(edKey.publicKey))

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecdhPubKey, err := ecdsaKey.PublicKey.ECDH()
	require.NoError(t, err)
	ecdsaPubBytes := ecdhPubKey.Bytes()
	ecdsaPubKey := mustParseSKECDSAPublicKey(t, ecdsaPubBytes, "ssh:")
	ecdsaPEM := marshalSKECDSAPrivateKey(t, ecdsaPubBytes, "ssh:", sshSkUserPresenceRequired, []byte("ec-handle"))

	parsedECDSAKey, err := parseSecurityKeyPrivateKey(ecdsaPEM, nil)
	require.NoError(t, err)
	assert.Equal(t, ssh.KeyAlgoSKECDSA256, parsedECDSAKey.publicKey.Type())
	assert.Equal(t, "ssh:", parsedECDSAKey.application)
	assert.Equal(t, byte(sshSkUserPresenceRequired), parsedECDSAKey.flags)
	assert.Equal(t, []byte("ec-handle"), parsedECDSAKey.keyHandle)
	assert.Equal(t, ssh.FingerprintSHA256(ecdsaPubKey), ssh.FingerprintSHA256(parsedECDSAKey.publicKey))
}

func TestParseSecurityKeyPrivateKeyRejectsMultiKeyFile(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubKey := mustParseSKEd25519PublicKey(t, pub, "ssh:")
	privBlock := ssh.Marshal(openSSHPrivateKey{
		Check1:  0x01020304,
		Check2:  0x01020304,
		Keytype: ssh.KeyAlgoSKED25519,
		Rest: ssh.Marshal(openSSHSKEd25519PrivateKey{
			Pub:         pub,
			Application: "ssh:",
			Flags:       sshSkUserPresenceRequired,
			KeyHandle:   []byte("ed-handle"),
			Comment:     "test",
			Pad:         []byte{1, 2, 3, 4},
		}),
	})
	encoded := append([]byte(privateKeyAuthMagic), ssh.Marshal(openSSHEncryptedPrivateKey{
		CipherName:   "none",
		KdfName:      "none",
		KdfOpts:      "",
		NumKeys:      2,
		PubKey:       pubKey.Marshal(),
		PrivKeyBlock: privBlock,
	})...)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: encoded})

	_, err = parseSecurityKeyPrivateKey(pemBytes, nil)
	require.EqualError(t, err, "ssh: multi-key files are not supported")
}

func TestSecurityKeySignerEd25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubKey := mustParseSKEd25519PublicKey(t, pub, "ssh:")
	privateKey := marshalSKEd25519PrivateKey(t, pub, "ssh:", sshSkUserPresenceRequired|sshSkUserVerificationRequired, []byte("ed-handle"))

	signer := newSecurityKeySignerWithProvider("", privateKey, pubKey, nil, fakeSecurityKeyProvider(
		func(algorithm, application string, flags byte, keyHandle, data []byte) (*securityKeySignResult, error) {
			assert.Equal(t, ssh.KeyAlgoSKED25519, algorithm)
			assert.Equal(t, "ssh:", application)
			assert.Equal(t, []byte("ed-handle"), keyHandle)
			payload := securityKeySignedPayload(application, flags, 7, data)
			return &securityKeySignResult{
				blob:    ed25519.Sign(priv, payload),
				flags:   flags,
				counter: 7,
			}, nil
		},
	))
	require.NotNil(t, signer)
	assert.Equal(t, ssh.FingerprintSHA256(pubKey), ssh.FingerprintSHA256(signer.PublicKey()))

	sig, err := signer.Sign(rand.Reader, []byte("hello security key"))
	require.NoError(t, err)
	require.NoError(t, signer.PublicKey().Verify([]byte("hello security key"), sig))
}

func TestSecurityKeySignerECDSA(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecdhPubKey, err := privateKey.PublicKey.ECDH()
	require.NoError(t, err)
	pubBytes := ecdhPubKey.Bytes()
	pubKey := mustParseSKECDSAPublicKey(t, pubBytes, "ssh:")
	skPrivateKey := marshalSKECDSAPrivateKey(t, pubBytes, "ssh:", sshSkUserPresenceRequired, []byte("ec-handle"))

	signer := newSecurityKeySignerWithProvider("", skPrivateKey, pubKey, nil, fakeSecurityKeyProvider(
		func(algorithm, application string, flags byte, keyHandle, data []byte) (*securityKeySignResult, error) {
			assert.Equal(t, ssh.KeyAlgoSKECDSA256, algorithm)
			assert.Equal(t, "ssh:", application)
			assert.Equal(t, []byte("ec-handle"), keyHandle)

			digest := sha256.Sum256(securityKeySignedPayload(application, flags, 11, data))
			r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
			require.NoError(t, err)
			der, err := asn1.Marshal(struct {
				R, S *big.Int
			}{R: r, S: s})
			require.NoError(t, err)
			return &securityKeySignResult{
				blob:    der,
				flags:   flags,
				counter: 11,
			}, nil
		},
	))
	require.NotNil(t, signer)
	assert.Equal(t, ssh.FingerprintSHA256(pubKey), ssh.FingerprintSHA256(signer.PublicKey()))

	sig, err := signer.Sign(rand.Reader, []byte("hello security key"))
	require.NoError(t, err)
	require.NoError(t, signer.PublicKey().Verify([]byte("hello security key"), sig))
}

func TestPassphraseProtectedSecurityKeySignerEd25519(t *testing.T) {
	passphrase := []byte("s3cret")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubKey := mustParseSKEd25519PublicKey(t, pub, "ssh:")
	privateKey := marshalEncryptedSKEd25519PrivateKey(
		t, pub, "ssh:", sshSkUserPresenceRequired|sshSkUserVerificationRequired, []byte("ed-handle"), passphrase,
	)

	signer := newSecurityKeySignerWithProvider("", privateKey, pubKey, passphrase, fakeSecurityKeyProvider(
		func(algorithm, application string, flags byte, keyHandle, data []byte) (*securityKeySignResult, error) {
			assert.Equal(t, ssh.KeyAlgoSKED25519, algorithm)
			assert.Equal(t, "ssh:", application)
			assert.Equal(t, []byte("ed-handle"), keyHandle)
			payload := securityKeySignedPayload(application, flags, 9, data)
			return &securityKeySignResult{
				blob:    ed25519.Sign(priv, payload),
				flags:   flags,
				counter: 9,
			}, nil
		},
	))
	require.NotNil(t, signer)

	sig, err := signer.Sign(rand.Reader, []byte("hello protected security key"))
	require.NoError(t, err)
	require.NoError(t, signer.PublicKey().Verify([]byte("hello protected security key"), sig))
}

func TestFindIdentityAgentSignerUsesSidecarPublicKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubKey := mustParseSKEd25519PublicKey(t, pub, "ssh:")

	dir := t.TempDir()
	path := filepath.Join(dir, "id_ed25519_sk")
	pubLine := ssh.MarshalAuthorizedKey(pubKey)
	require.NoError(t, os.WriteFile(path+".pub", pubLine, 0o600))

	signer, matchedPubKey := findIdentityAgentSigner(path, []ssh.Signer{staticSigner{pubKey: pubKey}})
	require.NotNil(t, signer)
	require.NotNil(t, matchedPubKey)
	assert.Equal(t, ssh.FingerprintSHA256(pubKey), ssh.FingerprintSHA256(matchedPubKey))
	assert.Equal(t, ssh.FingerprintSHA256(pubKey), ssh.FingerprintSHA256(signer.PublicKey()))
}

func TestExplicitIdentityDoesNotAddAllAgentSigners(t *testing.T) {
	restoreAgentClient := getAgentClientImpl
	defer func() { getAgentClientImpl = restoreAgentClient }()
	oldUserConfig := userConfig
	userConfig = &tsshConfig{}
	defer func() { userConfig = oldUserConfig }()

	otherPub, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	otherSigner, err := ssh.NewSignerFromKey(otherPriv)
	require.NoError(t, err)

	matchPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	matchPubKey := mustParseSKEd25519PublicKey(t, matchPub, "ssh:")

	dir := t.TempDir()
	path := filepath.Join(dir, "id_ed25519_sk")
	require.NoError(t, os.WriteFile(path, marshalSKEd25519PrivateKey(t, matchPub, "ssh:", sshSkUserPresenceRequired, []byte("match-handle")), 0o600))
	require.NoError(t, os.WriteFile(path+".pub", ssh.MarshalAuthorizedKey(matchPubKey), 0o600))

	getAgentClientImpl = func(*sshParam) agent.ExtendedAgent {
		return fakeExtendedAgent{
			signers: []ssh.Signer{
				staticSigner{pubKey: matchPubKey},
				otherSigner,
				staticSigner{pubKey: mustParseSKEd25519PublicKey(t, otherPub, "ssh:")},
			},
		}
	}

	param := &sshParam{
		args: &sshArgs{
			Destination: "dest",
			Identity:    multiStr{values: []string{path}},
		},
	}

	signers := getPublicKeySigners(param)
	require.Len(t, signers, 1)
	assert.Equal(t, ssh.FingerprintSHA256(matchPubKey), ssh.FingerprintSHA256(signers[0].PublicKey()))
}

func TestOpenSSHConfigSecurityKeyIdentityUsesMatchingAgentSigner(t *testing.T) {
	restoreAgentClient := getAgentClientImpl
	defer func() { getAgentClientImpl = restoreAgentClient }()
	oldUserConfig := userConfig
	userConfig = &tsshConfig{useOpenSSHConfig: true}
	defer func() { userConfig = oldUserConfig }()

	openSSHEffectiveCfgCache.mu.Lock()
	oldEffectiveCfg := openSSHEffectiveCfgCache.m
	openSSHEffectiveCfgCache.m = make(map[string]*effectiveSshConfig)
	openSSHEffectiveCfgCache.mu.Unlock()
	defer func() {
		openSSHEffectiveCfgCache.mu.Lock()
		openSSHEffectiveCfgCache.m = oldEffectiveCfg
		openSSHEffectiveCfgCache.mu.Unlock()
	}()

	otherPub, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	otherSigner, err := ssh.NewSignerFromKey(otherPriv)
	require.NoError(t, err)

	matchPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	matchPubKey := mustParseSKEd25519PublicKey(t, matchPub, "ssh:")

	dir := t.TempDir()
	path := filepath.Join(dir, "id_ed25519_sk")
	require.NoError(t, os.WriteFile(path, marshalSKEd25519PrivateKey(t, matchPub, "ssh:", sshSkUserPresenceRequired, []byte("match-handle")), 0o600))
	require.NoError(t, os.WriteFile(path+".pub", ssh.MarshalAuthorizedKey(matchPubKey), 0o600))

	openSSHEffectiveCfgCache.mu.Lock()
	openSSHEffectiveCfgCache.m["dest"] = &effectiveSshConfig{
		values: map[string][]string{
			"identitiesonly": {"yes"},
			"identityfile":   {path},
		},
	}
	openSSHEffectiveCfgCache.mu.Unlock()

	getAgentClientImpl = func(*sshParam) agent.ExtendedAgent {
		return fakeExtendedAgent{
			signers: []ssh.Signer{
				staticSigner{pubKey: matchPubKey},
				otherSigner,
				staticSigner{pubKey: mustParseSKEd25519PublicKey(t, otherPub, "ssh:")},
			},
		}
	}

	param := &sshParam{
		args: &sshArgs{
			Destination: "dest",
		},
	}

	signers := getPublicKeySigners(param)
	require.Len(t, signers, 1)
	assert.Equal(t, ssh.FingerprintSHA256(matchPubKey), ssh.FingerprintSHA256(signers[0].PublicKey()))
}

func TestParseSecurityKeyAuthData(t *testing.T) {
	authData := make([]byte, 37)
	authData[32] = sshSkUserPresenceRequired | sshSkUserVerificationRequired
	authData[33] = 0x01
	authData[34] = 0x02
	authData[35] = 0x03
	authData[36] = 0x04

	flags, counter, err := parseSecurityKeyAuthData(authData)
	require.NoError(t, err)
	assert.Equal(t, byte(sshSkUserPresenceRequired|sshSkUserVerificationRequired), flags)
	assert.Equal(t, uint32(0x01020304), counter)

	_, _, err = parseSecurityKeyAuthData([]byte{1, 2, 3})
	require.Error(t, err)
}

func securityKeySignedPayload(application string, flags byte, counter uint32, data []byte) []byte {
	applicationDigest := sha256.Sum256([]byte(application))
	messageDigest := sha256.Sum256(data)
	return ssh.Marshal(struct {
		ApplicationDigest []byte `ssh:"rest"`
		Flags             byte
		Counter           uint32
		MessageDigest     []byte `ssh:"rest"`
	}{
		ApplicationDigest: applicationDigest[:],
		Flags:             flags,
		Counter:           counter,
		MessageDigest:     messageDigest[:],
	})
}

func mustParseSKEd25519PublicKey(t *testing.T, pub []byte, application string) ssh.PublicKey {
	t.Helper()
	key, err := ssh.ParsePublicKey(ssh.Marshal(struct {
		Name        string
		KeyBytes    []byte
		Application string
	}{
		Name:        ssh.KeyAlgoSKED25519,
		KeyBytes:    pub,
		Application: application,
	}))
	require.NoError(t, err)
	return key
}

func mustParseSKECDSAPublicKey(t *testing.T, pub []byte, application string) ssh.PublicKey {
	t.Helper()
	key, err := ssh.ParsePublicKey(ssh.Marshal(struct {
		Name        string
		Curve       string
		KeyBytes    []byte
		Application string
	}{
		Name:        ssh.KeyAlgoSKECDSA256,
		Curve:       "nistp256",
		KeyBytes:    pub,
		Application: application,
	}))
	require.NoError(t, err)
	return key
}

func marshalSKEd25519PrivateKey(t *testing.T, pub []byte, application string, flags byte, keyHandle []byte) []byte {
	t.Helper()
	pubKey := mustParseSKEd25519PublicKey(t, pub, application)
	return marshalSKOpenSSHPrivateKey(t, pubKey, ssh.KeyAlgoSKED25519, openSSHSKEd25519PrivateKey{
		Pub:         pub,
		Application: application,
		Flags:       flags,
		KeyHandle:   keyHandle,
		Comment:     "test",
		Pad:         []byte{1, 2, 3, 4},
	})
}

func marshalEncryptedSKEd25519PrivateKey(
	t *testing.T, pub []byte, application string, flags byte, keyHandle, passphrase []byte,
) []byte {
	t.Helper()
	pubKey := mustParseSKEd25519PublicKey(t, pub, application)
	return marshalEncryptedSKOpenSSHPrivateKey(t, pubKey, ssh.KeyAlgoSKED25519, openSSHSKEd25519PrivateKey{
		Pub:         pub,
		Application: application,
		Flags:       flags,
		KeyHandle:   keyHandle,
		Comment:     "test",
		Pad:         []byte{1, 2, 3, 4},
	}, passphrase)
}

func marshalSKECDSAPrivateKey(t *testing.T, pub []byte, application string, flags byte, keyHandle []byte) []byte {
	t.Helper()
	pubKey := mustParseSKECDSAPublicKey(t, pub, application)
	return marshalSKOpenSSHPrivateKey(t, pubKey, ssh.KeyAlgoSKECDSA256, openSSHSKECDSAPrivateKey{
		Curve:       "nistp256",
		Pub:         pub,
		Application: application,
		Flags:       flags,
		KeyHandle:   keyHandle,
		Comment:     "test",
		Pad:         []byte{1, 2, 3, 4},
	})
}

func marshalSKOpenSSHPrivateKey(t *testing.T, pubKey ssh.PublicKey, keyType string, rest any) []byte {
	t.Helper()
	privBlock := ssh.Marshal(openSSHPrivateKey{
		Check1:  0x01020304,
		Check2:  0x01020304,
		Keytype: keyType,
		Rest:    ssh.Marshal(rest),
	})
	encoded := append([]byte(privateKeyAuthMagic), ssh.Marshal(openSSHEncryptedPrivateKey{
		CipherName:   "none",
		KdfName:      "none",
		KdfOpts:      "",
		NumKeys:      1,
		PubKey:       pubKey.Marshal(),
		PrivKeyBlock: privBlock,
	})...)
	return pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: encoded})
}

func marshalEncryptedSKOpenSSHPrivateKey(t *testing.T, pubKey ssh.PublicKey, keyType string, rest any, passphrase []byte) []byte {
	t.Helper()

	privBlock := ssh.Marshal(openSSHPrivateKey{
		Check1:  0x01020304,
		Check2:  0x01020304,
		Keytype: keyType,
		Rest:    ssh.Marshal(rest),
	})

	salt := []byte("0123456789abcdef")
	rounds := uint32(16)
	keyMaterial, err := bcryptPBKDFKey(passphrase, salt, int(rounds), 32+16)
	require.NoError(t, err)

	encrypted := append([]byte(nil), privBlock...)
	block, err := aes.NewCipher(keyMaterial[:32])
	require.NoError(t, err)
	cipher.NewCTR(block, keyMaterial[32:]).XORKeyStream(encrypted, encrypted)

	kdfOpts := ssh.Marshal(struct {
		Salt   string
		Rounds uint32
	}{
		Salt:   string(salt),
		Rounds: rounds,
	})

	encoded := append([]byte(privateKeyAuthMagic), ssh.Marshal(openSSHEncryptedPrivateKey{
		CipherName:   "aes256-ctr",
		KdfName:      "bcrypt",
		KdfOpts:      string(kdfOpts),
		NumKeys:      1,
		PubKey:       pubKey.Marshal(),
		PrivKeyBlock: encrypted,
	})...)
	return pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: encoded})
}

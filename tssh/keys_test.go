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
	"crypto/rand"
	"crypto/x509"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/testdata"
)

func TestParsePrivateKey_Normal(t *testing.T) {
	pemBytes := testdata.PEMBytes["rsa"]

	signer, err := parsePrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("parsePrivateKey failed: %v", err)
	}

	data := []byte("hello")
	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	if err := signer.PublicKey().Verify(data, sig); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
}

func TestParsePrivateKey_Encrypted(t *testing.T) {
	for _, tt := range testdata.PEMEncryptedKeys {
		t.Run(tt.Name, func(t *testing.T) {
			_, err := parsePrivateKey(tt.PEMBytes)
			if _, ok := err.(*ssh.PassphraseMissingError); !ok {
				t.Fatalf("expected PassphraseMissingError, got %T: %v", err, err)
			}
		})
	}
}

func TestParsePrivateKeyWithPassphrase(t *testing.T) {
	data := []byte("sign me")

	for _, tt := range testdata.PEMEncryptedKeys {
		t.Run(tt.Name, func(t *testing.T) {
			signer, err := parsePrivateKeyWithPassphrase(tt.PEMBytes, []byte(tt.EncryptionKey))
			if err != nil {
				t.Fatalf("parsePrivateKeyWithPassphrase failed: %v", err)
			}

			sig, err := signer.Sign(rand.Reader, data)
			if err != nil {
				t.Fatalf("sign failed: %v", err)
			}

			if err := signer.PublicKey().Verify(data, sig); err != nil {
				t.Fatalf("verify failed: %v", err)
			}
		})
	}
}

func TestParsePrivateKeyWithPassphrase_Incorrect(t *testing.T) {
	pemBytes := testdata.PEMEncryptedKeys[0].PEMBytes

	_, err := parsePrivateKeyWithPassphrase(pemBytes, []byte("wrong"))

	if err != x509.IncorrectPasswordError {
		t.Fatalf("expected IncorrectPasswordError, got %T: %v", err, err)
	}
}

var skTestCases = []struct {
	name string
	key  []byte
}{
	{"ECDSA-SK", []byte(`-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAfwAAACJzay1lY2
RzYS1zaGEyLW5pc3RwMjU2QG9wZW5zc2guY29tAAAACG5pc3RwMjU2AAAAQQSg1WuY0XE+
VexOsrJsFYuxyVoe6eQ/oXmyz2pEHKZw9moyWehv+Fs7oZWFp3JVmOtybKQ6dvfUZYauQE
/Ov4PAAAAABHNzaDoAAAGI6iV41+oleNcAAAAic2stZWNkc2Etc2hhMi1uaXN0cDI1NkBv
cGVuc3NoLmNvbQAAAAhuaXN0cDI1NgAAAEEEoNVrmNFxPlXsTrKybBWLsclaHunkP6F5ss
9qRBymcPZqMlnob/hbO6GVhadyVZjrcmykOnb31GWGrkBPzr+DwAAAAARzc2g6AQAAAOMt
LS0tLUJFR0lOIEVDIFBSSVZBVEUgS0VZLS0tLS0KTUhjQ0FRRUVJQm9oeW54M2tpTFVEeS
t5UjU3WXBXSU5KektnU1p6WnV2VTljYXFla3JGcW9Bb0dDQ3FHU000OQpBd0VIb1VRRFFn
QUVvTlZybU5GeFBsWHNUckt5YkJXTHNjbGFIdW5rUDZGNXNzOXFSQnltY1BacU1sbm9iL2
hiCk82R1ZoYWR5VlpqcmNteWtPbmIzMUdXR3JrQlB6citEd0E9PQotLS0tLUVORCBFQyBQ
UklWQVRFIEtFWS0tLS0tCgAAAAAAAAARRUNEU0EtU0sgdGVzdCBrZXk=
-----END OPENSSH PRIVATE KEY-----`)},
	{"ED25519-SK", []byte(`-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAASgAAABpzay1zc2
gtZWQyNTUxOUBvcGVuc3NoLmNvbQAAACCbGg2F0GK7nOm4pQmAyCuGEjnhvs5q0TtjPbdN
//+yxwAAAARzc2g6AAAAuBw56jAcOeowAAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY2
9tAAAAIJsaDYXQYruc6bilCYDIK4YSOeG+zmrRO2M9t03//7LHAAAABHNzaDoBAAAAQFXc
6dCwWewIk1EBofAouGZApW8+s0XekXenxtb78+x0mxoNhdBiu5zpuKUJgMgrhhI54b7Oat
E7Yz23Tf//sscAAAAAAAAAE0VEMjU1MTktU0sgdGVzdCBrZXkBAgMEBQY=
-----END OPENSSH PRIVATE KEY-----`)},
}

func TestParsePrivateKey_TriggersFallback(t *testing.T) {
	for _, tt := range skTestCases {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ssh.ParsePrivateKey(tt.key); err == nil || err.Error() != kUnhandledKeyTypeError {
				t.Fatalf("unexpected upstream error: %v", err)
			}
			_, err := parsePrivateKey(tt.key)
			if _, ok := err.(*unhandledSecurityKeyError); !ok {
				t.Fatalf("fallback not working, got %T: %v", err, err)
			}
		})
	}
}

func TestParsePrivateKey_SKKey(t *testing.T) {
	for _, tt := range skTestCases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parsePrivateKey(tt.key)
			if err == nil {
				t.Fatalf("expected error for security key type")
			}

			skErr, ok := err.(*unhandledSecurityKeyError)
			if !ok {
				t.Fatalf("expected unhandledSecurityKeyError, got %T: %v", err, err)
			}

			if shortKeyType(skErr.KeyType) != tt.name {
				t.Fatalf("unexpected key type: got %s, want %s", shortKeyType(skErr.KeyType), tt.name)
			}

			signer, err := parseSecurityKey("", skErr)
			if err != nil {
				t.Fatalf("parse security key error: %v", err)
			}

			if signer.keyFlags != 1 { // SSH_SK_USER_PRESENCE_REQD = 1
				t.Fatalf("unexpected keyFlags: got=%d want=%d", signer.keyFlags, 1)
			}
		})
	}
}

var skPassphraseTestCases = []struct {
	name string
	key  []byte
}{
	{"ECDSA-SK", []byte(`-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCHY+Ogcw
BBKGS/g8XyuIElAAAAGAAAAAEAAAB/AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3Bl
bnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBKDVa5jRcT5V7E6ysmwVi7HJWh7p5D+hebLPak
QcpnD2ajJZ6G/4WzuhlYWnclWY63JspDp299Rlhq5AT86/g8AAAAAEc3NoOgAAAZC3gh1l
7NlfRw4WJKlOpy4SAEPGIUSfBAdRi8v4WAHvev1w8kKBDOCrIlZemLP+QblPC8y8GSWvYm
74i/YyA3dVs/oMcJ72zWUCuG9CIMmiFf/fwbSpKyHoFOUZlhNIrKFOQe/eVla+8xiJUYsY
dq1Hz3zoJJ9Im9t8AtG2dyUfTLEVpxImjbKuE664sqjPJ62j39iuY8iLQSuu8kyI3102+B
duAB8AWUE12/TjwZRlbeBhY2i89MlrpNtmP+Oj8AH8cRhTr2iMTRrcBaF5FA+M9LxnlW8r
2qyK5/GZSqRQEqHzQ9ttqcWoq2kGZsdQvdVd8VjUn1hgk+xPh6zY7lxOH1S39NsNY+ef0I
O/6XLQO8fWikHKXT27+6yzCEx6aJZE3LHe/RJzhLEbzkuRyqLcJY9v1DEYqNhObSBQTBIS
wXY96qw5bTypaobihzePyTxkk08UcgJL4XmbxPGZ+TCUbTebGsYJ2G3wTokK2eFl1iyWNH
kzgBtutmUNGeoP++NQ1glTDfUh11+94mZameLZ
-----END OPENSSH PRIVATE KEY-----`)},
	{"ED25519-SK", []byte(`-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABD3pqcmQr
tPigtdmfZb5YMYAAAAGAAAAAEAAABKAAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29t
AAAAIJsaDYXQYruc6bilCYDIK4YSOeG+zmrRO2M9t03//7LHAAAABHNzaDoAAADAnktUoQ
jS7LzjFz3sMrmeAw3DZUT+xFlpAXK2xCmzd0u5QK4yts4il3KVUOsgHMo89EU3CIfFBn7J
e2X+QV/WX6GtomuL8r7fVF2Z1qCboyMQtgMx4NlknwPirOm/KUqHD8LKI/yDgH2m/sHxSO
af5qShnqlXfy/H04lZBQ/ZkIb5s/yrvvxP4OpN2Gso5AVQ9Ygc+ZG47G8VShpF91+7l92+
zJR7a0E+wT811plmUJdb3q21351xuosV6Cg8r1J5
-----END OPENSSH PRIVATE KEY-----`)},
}

func TestParsePrivateKeyWithPassphrase_SKKey(t *testing.T) {
	for _, tt := range skPassphraseTestCases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parsePrivateKeyWithPassphrase(tt.key, []byte("123456"))
			if err == nil {
				t.Fatalf("expected error for security key type")
			}

			skErr, ok := err.(*unhandledSecurityKeyError)
			if !ok {
				t.Fatalf("expected unhandledSecurityKeyError, got %T: %v", err, err)
			}

			if shortKeyType(skErr.KeyType) != tt.name {
				t.Fatalf("unexpected key type: got %s, want %s", shortKeyType(skErr.KeyType), tt.name)
			}

			signer, err := parseSecurityKey("", skErr)
			if err != nil {
				t.Fatalf("parse security key error: %v", err)
			}

			if signer.keyFlags != 1 { // SSH_SK_USER_PRESENCE_REQD = 1
				t.Fatalf("unexpected keyFlags: got=%d want=%d", signer.keyFlags, 1)
			}
		})
	}
}

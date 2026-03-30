//go:build windows

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
	"fmt"
	"log/slog"
	"time"

	"github.com/go-ctap/ctaphid/pkg/webauthntypes"
	"github.com/go-ctap/winhello"
	"github.com/go-ctap/winhello/hiddenwindow"
	"golang.org/x/crypto/ssh"
)

type winHelloSecurityKeyProvider struct{}

func hasSecurityKeyProvider() bool {
	return true
}

func newSecurityKeyProvider() securityKeyProvider {
	return winHelloSecurityKeyProvider{}
}

func (winHelloSecurityKeyProvider) Sign(algorithm, application string, flags byte, keyHandle, data []byte) (*securityKeySignResult, error) {
	switch algorithm {
	case ssh.KeyAlgoSKED25519, ssh.KeyAlgoSKECDSA256:
	default:
		return nil, fmt.Errorf("unsupported security key algorithm: %s", algorithm)
	}
	if application == "" {
		return nil, fmt.Errorf("security key application is empty")
	}
	if len(keyHandle) == 0 {
		return nil, fmt.Errorf("security key handle is empty")
	}

	if flags&sshSkUserPresenceRequired == 0 {
		debug("windows hello does not support no-touch-required security keys; interaction may still be required")
	}

	window, err := hiddenwindow.New(slog.New(slog.DiscardHandler), "tssh Security Key")
	if err != nil {
		return nil, err
	}
	defer window.Close()

	verification := winhello.WinHelloUserVerificationRequirementDiscouraged
	if flags&sshSkUserVerificationRequired != 0 {
		verification = winhello.WinHelloUserVerificationRequirementRequired
	}

	assertion, err := winhello.GetAssertion(
		window.WindowHandle(),
		application,
		data,
		[]webauthntypes.PublicKeyCredentialDescriptor{{
			ID:   keyHandle,
			Type: webauthntypes.PublicKeyCredentialTypePublicKey,
		}},
		nil,
		&winhello.AuthenticatorGetAssertionOptions{
			Timeout:                      60 * time.Second,
			AuthenticatorAttachment:      winhello.WinHelloAuthenticatorAttachmentAny,
			UserVerificationRequirement:  verification,
			CredentialLargeBlobOperation: winhello.WinHelloCredentialLargeBlobOperationNone,
		},
	)
	if err != nil {
		return nil, err
	}

	assertionFlags, assertionCounter, err := parseSecurityKeyAuthData(assertion.AuthDataRaw)
	if err != nil {
		return nil, err
	}

	return &securityKeySignResult{
		blob:    assertion.Signature,
		flags:   assertionFlags,
		counter: assertionCounter,
	}, nil
}

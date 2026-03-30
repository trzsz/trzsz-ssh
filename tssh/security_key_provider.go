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
	"encoding/binary"
	"fmt"
)

const (
	sshSkUserPresenceRequired     = 0x01
	sshSkUserVerificationRequired = 0x04
)

type securityKeySignResult struct {
	blob    []byte
	flags   byte
	counter uint32
}

type securityKeyProvider interface {
	Sign(algorithm, application string, flags byte, keyHandle, data []byte) (*securityKeySignResult, error)
}

func parseSecurityKeyAuthData(authData []byte) (flags byte, counter uint32, err error) {
	// WebAuthn/FIDO2 authenticator data starts with:
	// 32-byte rpIdHash, 1-byte flags, 4-byte signature counter.
	if len(authData) < 37 {
		return 0, 0, fmt.Errorf("invalid security key authdata length: %d", len(authData))
	}
	return authData[32], binary.BigEndian.Uint32(authData[33:37]), nil
}

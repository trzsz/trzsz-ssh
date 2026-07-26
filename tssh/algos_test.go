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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
)

func TestSetupAlgorithmsConfig(t *testing.T) {

	if userConfig == nil {
		userConfig = &tsshConfig{}
		defer func() { userConfig = nil }()
	}

	// 1. Get the underlying default values of ssh.ClientConfig
	// Doing this dynamically ensures tests won't break if Go updates default algorithms.
	baseConfig := &ssh.ClientConfig{}
	baseConfig.SetDefaults()
	defaultCiphers := baseConfig.Ciphers
	defaultKex := baseConfig.KeyExchanges

	// 2. Helper function to prepare expected results for the '-' (remove) operation
	filterOutPrefix := func(base []string, prefix string) []string {
		var res []string
		for _, v := range base {
			if !strings.HasPrefix(v, prefix) {
				res = append(res, v)
			}
		}
		return res
	}

	// 3. Define table-driven test cases
	tests := []struct {
		name            string
		args            *sshArgs
		expectedCiphers []string
		expectedKex     []string
		expectError     bool
	}{
		{
			name:            "Empty config, should keep defaults",
			args:            &sshArgs{},
			expectedCiphers: defaultCiphers,
			expectedKex:     defaultKex,
			expectError:     false,
		},
		{
			name: "Full replace Ciphers",
			args: &sshArgs{
				CipherSpec: "aes128-ctr,aes192-ctr",
			},
			expectedCiphers: []string{"aes128-ctr", "aes192-ctr"},
			expectedKex:     defaultKex,
			expectError:     false,
		},
		{
			name: "Append (+) Ciphers",
			args: &sshArgs{
				CipherSpec: "+aes128-cbc",
			},
			// Expected: default list + new items
			expectedCiphers: append(append([]string(nil), defaultCiphers...), "aes128-cbc"),
			expectedKex:     defaultKex,
			expectError:     false,
		},
		{
			name: "Insert (^) KexAlgorithms at the beginning, testing space filtering",
			args: &sshArgs{
				// Testing edge cases with extra spaces around the items
				Option: sshOption{
					options: map[string][]string{
						"kexalgorithms": {"^ diffie-hellman-group1-sha1 , diffie-hellman-group-exchange-sha1 "},
					},
				},
			},
			// Expected: new items + default list
			expectedCiphers: defaultCiphers,
			expectedKex: append([]string{"diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1"},
				defaultKex...),
			expectError: false,
		},
		{
			name: "Remove (-) Ciphers (supports regex wildcard prefix)",
			args: &sshArgs{
				// Assuming wildcardToRegexp converts 'aes*' to 'aes.*'
				// Here we remove all encryption algorithms starting with "aes"
				CipherSpec: "-aes*",
			},
			expectedCiphers: filterOutPrefix(defaultCiphers, "aes"),
			expectedKex:     defaultKex,
			expectError:     false,
		},
		{
			name: "Modify both Ciphers and KexAlgorithms simultaneously",
			args: &sshArgs{
				CipherSpec: "aes128-ctr", // Explicitly testing the implicit/explicit replacement logic
				Option: sshOption{
					options: map[string][]string{
						"kexalgorithms": {"+diffie-hellman-group-exchange-sha256"},
					},
				},
			},
			expectedCiphers: []string{"aes128-ctr"},
			expectedKex:     append(append([]string(nil), defaultKex...), "diffie-hellman-group-exchange-sha256"),
			expectError:     false,
		},
		{
			name: "Only commas and spaces after operator, should not panic",
			args: &sshArgs{
				CipherSpec: "- ,  ,",
			},
			// Equivalent to no substantial removal due to strings.TrimSpace and empty checks
			expectedCiphers: defaultCiphers,
			expectedKex:     defaultKex,
			expectError:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			// Initialize an empty config instance
			config := &ssh.ClientConfig{}

			// Execute the target function
			err := setupAlgorithmsConfig(tt.args, config)

			// Check if the error status matches the expectation
			if (err != nil) != tt.expectError {
				t.Fatalf("expected error: %v, got: %v", tt.expectError, err)
			}

			// Call SetDefaults() to populate the default algorithm lists
			// before comparing them against expected results.
			config.SetDefaults()

			// Check if Ciphers match perfectly
			assert.Equal(tt.expectedCiphers, config.Ciphers)

			// Check if KeyExchanges match perfectly
			assert.Equal(tt.expectedKex, config.KeyExchanges)
		})
	}
}

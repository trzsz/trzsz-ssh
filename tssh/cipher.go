/*
MIT License

Copyright (c) 2023-2024 The Trzsz SSH Authors.

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
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
)

func debugCiphersConfig(config *ssh.ClientConfig) {
	if !enableDebugLogging {
		return
	}
	debug("user declared ciphers: %v", config.Ciphers)
	config.SetDefaults()
	debug("client supported ciphers: %v", config.Ciphers)
}

func appendCiphersConfig(config *ssh.ClientConfig, cipherSpec string) error {
	config.SetDefaults()
	for _, cipher := range strings.Split(cipherSpec, ",") {
		cipher = strings.TrimSpace(cipher)
		if cipher != "" {
			config.Ciphers = append(config.Ciphers, cipher)
		}
	}
	debugCiphersConfig(config)
	return nil
}

func removeCiphersConfig(config *ssh.ClientConfig, cipherSpec string) error {
	var buf strings.Builder
	for _, cipher := range strings.Split(cipherSpec, ",") {
		if buf.Len() > 0 {
			buf.WriteRune('|')
		}
		buf.WriteString("(^")
		for _, c := range cipher {
			switch c {
			case '*':
				buf.WriteString(".*")
			case '?':
				buf.WriteRune('.')
			case '(', ')', '[', ']', '{', '}', '.', '+', ',', '-', '^', '$', '|', '\\':
				buf.WriteRune('\\')
				buf.WriteRune(c)
			default:
				buf.WriteRune(c)
			}
		}
		buf.WriteString("$)")
	}
	expr := buf.String()
	debug("ciphers regexp: %s", expr)
	re, err := regexp.Compile(expr)
	if err != nil {
		return fmt.Errorf("compile ciphers regexp failed: %v", err)
	}

	config.SetDefaults()
	ciphers := make([]string, 0)
	for _, cipher := range config.Ciphers {
		if re.MatchString(cipher) {
			continue
		}
		ciphers = append(ciphers, cipher)
	}
	config.Ciphers = ciphers
	debugCiphersConfig(config)
	return nil
}

func insertCiphersConfig(config *ssh.ClientConfig, cipherSpec string) error {
	var ciphers []string
	for _, cipher := range strings.Split(cipherSpec, ",") {
		cipher = strings.TrimSpace(cipher)
		if cipher != "" {
			ciphers = append(ciphers, cipher)
		}
	}
	config.SetDefaults()
	config.Ciphers = append(ciphers, config.Ciphers...)
	debugCiphersConfig(config)
	return nil
}

func replaceCiphersConfig(config *ssh.ClientConfig, cipherSpec string) error {
	config.Ciphers = nil
	for _, cipher := range strings.Split(cipherSpec, ",") {
		cipher = strings.TrimSpace(cipher)
		if cipher != "" {
			config.Ciphers = append(config.Ciphers, cipher)
		}
	}
	debugCiphersConfig(config)
	return nil
}

func getCiphersConfig(args *sshArgs) string {
	if args.CipherSpec != "" {
		return args.CipherSpec
	}
	return getOptionConfig(args, "Ciphers")
}

func setupCiphersConfig(args *sshArgs, config *ssh.ClientConfig) error {
	cipherSpec := getCiphersConfig(args)
	if cipherSpec == "" {
		return nil
	}
	switch cipherSpec[0] {
	case '+':
		return appendCiphersConfig(config, cipherSpec[1:])
	case '-':
		return removeCiphersConfig(config, cipherSpec[1:])
	case '^':
		return insertCiphersConfig(config, cipherSpec[1:])
	default:
		return replaceCiphersConfig(config, cipherSpec)
	}
}

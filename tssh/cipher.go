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
	"fmt"
	"regexp"
	"strings"

	"github.com/trzsz/ssh_config"
	"golang.org/x/crypto/ssh"
)

func appendCiphersConfig(config *ssh.ClientConfig, cipherSpec string) error {
	config.SetDefaults()
	for cipher := range strings.SplitSeq(cipherSpec, ",") {
		cipher = strings.TrimSpace(cipher)
		if cipher != "" {
			config.Ciphers = append(config.Ciphers, cipher)
		}
	}
	return nil
}

func removeCiphersConfig(config *ssh.ClientConfig, cipherSpec string) error {
	var buf strings.Builder
	for cipher := range strings.SplitSeq(cipherSpec, ",") {
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
	re, err := regexp.Compile(expr)
	if err != nil {
		return fmt.Errorf("compile ciphers regexp [%s] failed: %v", expr, err)
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
	return nil
}

func insertCiphersConfig(config *ssh.ClientConfig, cipherSpec string) error {
	var ciphers []string
	for cipher := range strings.SplitSeq(cipherSpec, ",") {
		cipher = strings.TrimSpace(cipher)
		if cipher != "" {
			ciphers = append(ciphers, cipher)
		}
	}
	config.SetDefaults()
	config.Ciphers = append(ciphers, config.Ciphers...)
	return nil
}

func replaceCiphersConfig(config *ssh.ClientConfig, cipherSpec string) error {
	config.Ciphers = nil
	for cipher := range strings.SplitSeq(cipherSpec, ",") {
		cipher = strings.TrimSpace(cipher)
		if cipher != "" {
			config.Ciphers = append(config.Ciphers, cipher)
		}
	}
	return nil
}

func getCiphersConfig(args *sshArgs) string {
	if args.CipherSpec != "" {
		return args.CipherSpec
	}
	ssh_config.SetDefault("Ciphers", "")
	return getOptionConfig(args, "Ciphers")
}

func setupCiphersConfig(args *sshArgs, config *ssh.ClientConfig) (err error) {
	cipherSpec := getCiphersConfig(args)
	if cipherSpec == "" {
		return nil
	}
	if enableDebugLogging {
		config.SetDefaults()
		debug("default ciphers for [%s]: %s", args.Destination, strings.Join(config.Ciphers, " "))
		debug("customs ciphers for [%s]: %s", args.Destination, cipherSpec)
	}
	switch cipherSpec[0] {
	case '+':
		err = appendCiphersConfig(config, cipherSpec[1:])
	case '-':
		err = removeCiphersConfig(config, cipherSpec[1:])
	case '^':
		err = insertCiphersConfig(config, cipherSpec[1:])
	default:
		err = replaceCiphersConfig(config, cipherSpec)
	}
	if enableDebugLogging {
		config.SetDefaults()
		debug("current ciphers for [%s]: %s", args.Destination, strings.Join(config.Ciphers, " "))
	}
	return
}

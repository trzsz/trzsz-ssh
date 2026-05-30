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
	"regexp"
	"strings"

	"github.com/trzsz/ssh_config"
	"golang.org/x/crypto/ssh"
)

// modifyAlgorithmList handles the common +, -, ^, and replace logic.
func modifyAlgorithmList(baseList []string, spec string) ([]string, error) {
	if spec == "" {
		return baseList, nil
	}

	operator := spec[0]
	var listStr string
	if operator == '+' || operator == '-' || operator == '^' {
		listStr = spec[1:]
	} else {
		operator = '=' // Implicit replace
		listStr = spec
	}

	// Extract elements to be processed
	var elements []string
	for item := range strings.SplitSeq(listStr, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			elements = append(elements, item)
		}
	}

	switch operator {
	case '+': // Append
		return uniqueAlgorithms(append(baseList, elements...)), nil

	case '^': // Insert at the beginning
		return uniqueAlgorithms(append(elements, baseList...)), nil

	case '=': // Full replace
		return elements, nil

	case '-': // Remove
		if len(elements) == 0 {
			return baseList, nil
		}
		var buf strings.Builder
		for i, item := range elements {
			if i > 0 {
				buf.WriteRune('|')
			}
			buf.WriteString("(^")
			buf.WriteString(wildcardToRegexp(item))
			buf.WriteString("$)")
		}
		expr := buf.String()
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("compile regexp [%s] failed: %v", expr, err)
		}

		var result []string
		for _, item := range baseList {
			if !re.MatchString(item) {
				result = append(result, item)
			}
		}
		return result, nil
	}

	return baseList, nil
}

// uniqueAlgorithms removes duplicate algorithms while preserving the order of the first occurrence.
func uniqueAlgorithms(list []string) []string {
	keys := make(map[string]bool)
	var res []string
	for _, entry := range list {
		if !keys[entry] {
			keys[entry] = true
			res = append(res, entry)
		}
	}
	return res
}

func getCiphersConfig(args *sshArgs) string {
	if args.CipherSpec != "" {
		return args.CipherSpec
	}
	ssh_config.SetDefault("Ciphers", "")
	return getOptionConfig(args, "Ciphers")
}

func getKexAlgorithmsConfig(args *sshArgs) string {
	ssh_config.SetDefault("KexAlgorithms", "")
	return getOptionConfig(args, "KexAlgorithms")
}

// setupAlgorithmsConfig centrally handles all algorithm configurations (Ciphers, KexAlgorithms)
func setupAlgorithmsConfig(args *sshArgs, config *ssh.ClientConfig) error {
	cipherSpec := getCiphersConfig(args)
	kexSpec := getKexAlgorithmsConfig(args)

	if cipherSpec == "" && kexSpec == "" {
		return nil
	}

	// Initialize the default lists first to ensure baseList has data for +, -, ^ operations
	config.SetDefaults()

	// 1. Handle Ciphers
	if cipherSpec != "" {
		if enableDebugLogging {
			debug("default ciphers for [%s]: %s", args.Destination, strings.Join(config.Ciphers, " "))
			debug("request ciphers for [%s]: %s", args.Destination, cipherSpec)
		}

		newCiphers, err := modifyAlgorithmList(config.Ciphers, cipherSpec)
		if err != nil {
			return fmt.Errorf("ciphers config error: %w", err)
		}
		config.Ciphers = newCiphers

		if enableDebugLogging {
			config.SetDefaults()
			debug("current ciphers for [%s]: %s", args.Destination, strings.Join(config.Ciphers, " "))
		}
	}

	// 2. Handle KeyExchanges
	if kexSpec != "" {
		if enableDebugLogging {
			debug("default kex for [%s]: %s", args.Destination, strings.Join(config.KeyExchanges, " "))
			debug("request kex for [%s]: %s", args.Destination, kexSpec)
		}

		newKex, err := modifyAlgorithmList(config.KeyExchanges, kexSpec)
		if err != nil {
			return fmt.Errorf("kex config error: %w", err)
		}
		config.KeyExchanges = newKex

		if enableDebugLogging {
			config.SetDefaults()
			debug("current kex for [%s]: %s", args.Destination, strings.Join(config.KeyExchanges, " "))
		}
	}

	return nil
}

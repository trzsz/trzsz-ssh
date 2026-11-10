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
	"crypto/sha1"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode"
)

func isHostValid(host string) bool {
	if strings.HasPrefix(host, "-") {
		return false
	}
	for _, ch := range host {
		if strings.ContainsRune("'`\"$\\;&<>|(){}", ch) {
			return false
		}
		if unicode.IsSpace(ch) || unicode.IsControl(ch) {
			return false
		}
	}
	return true
}

func isUserValid(user string) bool {
	if strings.HasPrefix(user, "-") {
		return false
	}
	if strings.ContainsAny(user, "'`\";&<>|(){}") {
		return false
	}
	// disallow '-' after whitespace
	if regexp.MustCompile(`\s-`).MatchString(user) {
		return false
	}
	// disallow \ in last position
	if strings.HasSuffix(user, "\\") {
		return false
	}
	return true
}

func isPortValid(port string) bool {
	for _, ch := range port {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

var getHostname = func() string {
	hostname, err := os.Hostname()
	if err != nil {
		warning("get hostname failed: %v", err)
		return ""
	}
	return hostname
}

// supportsTokenJ reports whether the local OpenSSH client supports the %j token.
// If the version cannot be determined, assume support to avoid unnecessarily
// restricting token expansion.
func supportsTokenJ() bool {
	_, majorVersion, minorVersion, err := getOpenSSH()
	if err != nil || majorVersion < 0 || minorVersion < 0 {
		return true
	}
	if majorVersion > 9 || (majorVersion == 9 && minorVersion >= 6) {
		return true
	}
	return false
}

// jumpHostOf extracts the host from a proxy jump specification like
// [user@]host[:port], the same way OpenSSH derives options.jump_host in
// parse_jump(), so that the %C hash matches OpenSSH exactly.
func jumpHostOf(spec string) string {
	if idx := strings.LastIndexByte(spec, '@'); idx >= 0 {
		spec = spec[idx+1:]
	}
	if strings.HasPrefix(spec, "[") { // ipv6 literal, e.g. [::1]:2222
		if idx := strings.IndexByte(spec, ']'); idx > 0 {
			return spec[1:idx]
		}
		return spec[1:]
	}
	if idx := strings.IndexByte(spec, ':'); idx >= 0 {
		spec = spec[:idx]
	}
	return spec
}

func expandTokens(str string, param *sshParam, tokens string) (string, error) {
	return expandTokensInternal(str, param, tokens, nil, false)
}

func expandTokensWithCaptures(str string, param *sshParam, tokens string, captures map[string]string) (string, error) {
	return expandTokensInternal(str, param, tokens, captures, false)
}

// expandTokensForRegex expands ssh tokens into literal text for a regular
// expression: expanded values are escaped with regexp.QuoteMeta so that
// characters like '.' in an IP address do not act as metacharacters.
func expandTokensForRegex(str string, param *sshParam, tokens string) (string, error) {
	return expandTokensInternal(str, param, tokens, nil, true)
}

func expandTokensInternal(str string, param *sshParam, tokens string, captures map[string]string, escape bool) (string, error) {
	if !strings.ContainsRune(str, '%') {
		return str, nil
	}
	var buf strings.Builder
	writeValue := func(value string) {
		if escape {
			value = regexp.QuoteMeta(value)
		}
		buf.WriteString(value)
	}
	runes := []rune(str)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		if c != '%' {
			buf.WriteRune(c)
			continue
		}
		i++
		if i >= len(runes) {
			return "", fmt.Errorf("[%s] ends with %% is invalid", str)
		}
		c = runes[i]
		if captures != nil {
			if c >= '1' && c <= '9' {
				value, ok := captures[string(c)]
				if !ok {
					return "", fmt.Errorf("capture [%%%c] in [%s] is not found", c, str)
				}
				buf.WriteString(value)
				continue
			}
			if c == '{' {
				j := i + 1
				for j < len(runes) && runes[j] != '}' {
					j++
				}
				if j >= len(runes) {
					return "", fmt.Errorf("capture [%%{%s}] in [%s] is not closed", string(runes[i+1:]), str)
				}
				name := string(runes[i+1 : j])
				if name == "" {
					return "", fmt.Errorf("capture name [%%{}] in [%s] is empty", str)
				}
				value, ok := captures[name]
				if !ok {
					return "", fmt.Errorf("capture [%%{%s}] in [%s] is not found", name, str)
				}
				buf.WriteString(value)
				i = j
				continue
			}
		}
		if !strings.ContainsRune(tokens, c) {
			return "", fmt.Errorf("token [%%%c] in [%s] is not supported", c, str)
		}
		switch c {
		case '%':
			buf.WriteRune('%')
		case 'h':
			if !isHostValid(param.host) {
				return "", fmt.Errorf("host [%s] contains invalid characters", param.host)
			}
			writeValue(param.host)
		case 'p':
			if !isPortValid(param.port) {
				return "", fmt.Errorf("port [%s] contains invalid characters", param.port)
			}
			writeValue(param.port)
		case 'r':
			if !isUserValid(param.user) {
				return "", fmt.Errorf("user [%s] contains invalid characters", param.user)
			}
			writeValue(param.user)
		case 'n':
			if !isHostValid(param.args.Destination) {
				return "", fmt.Errorf("destination [%s] contains invalid characters", param.args.Destination)
			}
			writeValue(param.args.Destination)
		case 'l':
			writeValue(getHostname())
		case 'L':
			hostname := getHostname()
			if idx := strings.IndexByte(hostname, '.'); idx >= 0 {
				hostname = hostname[:idx]
			}
			writeValue(hostname)
		case 'j':
			if len(param.proxies) > 0 {
				if !supportsTokenJ() {
					return "", fmt.Errorf("local OpenSSH client [%s] is too old; %%j is not supported for compatibility", openSshPath)
				}
				proxy := jumpHostOf(param.proxies[len(param.proxies)-1])
				if !isHostValid(proxy) {
					return "", fmt.Errorf("proxy [%s] contains invalid characters", proxy)
				}
				writeValue(proxy)
			}
		case 'C':
			hashStr := fmt.Sprintf("%s%s%s%s", getHostname(), param.host, param.port, param.user)
			// OpenSSH 9.6 and later include the jump host in the %C hash.
			if len(param.proxies) > 0 && supportsTokenJ() {
				hashStr += jumpHostOf(param.proxies[len(param.proxies)-1])
			}
			writeValue(fmt.Sprintf("%x", sha1.Sum([]byte(hashStr))))
		case 'k':
			if hostKeyAlias := getOptionConfig(param.args, "HostKeyAlias"); hostKeyAlias != "" {
				if !isHostValid(hostKeyAlias) {
					return "", fmt.Errorf("HostKeyAlias [%s] contains invalid characters", hostKeyAlias)
				}
				writeValue(hostKeyAlias)
			} else {
				if !isHostValid(param.args.Destination) {
					return "", fmt.Errorf("destination [%s] contains invalid characters", param.args.Destination)
				}
				writeValue(param.args.Destination)
			}
		default:
			return "", fmt.Errorf("token [%%%c] in [%s] is not supported yet", c, str)
		}
	}
	return buf.String(), nil
}

func containsToken(s string, token byte) bool {
	for i, n := 0, len(s)-1; i < n; i++ {
		if s[i] != '%' {
			continue
		}
		i++
		switch s[i] {
		case '%':
			// skip %%
		case token:
			return true
		}
	}
	return false
}

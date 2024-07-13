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

var getHostname = func() string {
	hostname, err := os.Hostname()
	if err != nil {
		warning("get hostname failed: %v", err)
		return ""
	}
	return hostname
}

func expandTokens(str string, args *sshArgs, param *sshParam, tokens string) (string, error) {
	if !strings.ContainsRune(str, '%') {
		return str, nil
	}
	var buf strings.Builder
	state := byte(0)
	for _, c := range str {
		if state == 0 {
			switch c {
			case '%':
				state = '%'
			default:
				buf.WriteRune(c)
			}
			continue
		}
		state = 0
		if !strings.ContainsRune(tokens, c) {
			return str, fmt.Errorf("token [%%%c] in [%s] is not supported", c, str)
		}
		switch c {
		case '%':
			buf.WriteRune('%')
		case 'h':
			if !isHostValid(param.host) {
				return str, fmt.Errorf("hostname contains invalid characters")
			}
			buf.WriteString(param.host)
		case 'p':
			buf.WriteString(param.port)
		case 'r':
			if !isUserValid(param.user) {
				return str, fmt.Errorf("remote username contains invalid characters")
			}
			buf.WriteString(param.user)
		case 'n':
			buf.WriteString(args.Destination)
		case 'l':
			buf.WriteString(getHostname())
		case 'L':
			hostname := getHostname()
			if idx := strings.IndexByte(hostname, '.'); idx >= 0 {
				hostname = hostname[:idx]
			}
			buf.WriteString(hostname)
		case 'j':
			if len(param.proxy) > 0 {
				buf.WriteString(param.proxy[len(param.proxy)-1])
			}
		case 'C':
			hashStr := fmt.Sprintf("%s%s%s%s", getHostname(), param.host, param.port, param.user)
			if len(param.proxy) > 0 && strings.ContainsRune(tokens, 'j') {
				hashStr += param.proxy[len(param.proxy)-1]
			}
			buf.WriteString(fmt.Sprintf("%x", sha1.Sum([]byte(hashStr))))
		default:
			return str, fmt.Errorf("token [%%%c] in [%s] is not supported yet", c, str)
		}
	}
	if state != 0 {
		return str, fmt.Errorf("[%s] ends with %% is invalid", str)
	}
	return buf.String(), nil
}

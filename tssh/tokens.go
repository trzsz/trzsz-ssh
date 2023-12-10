/*
MIT License

Copyright (c) 2023 Lonny Wong <lonnywong@qq.com>
Copyright (c) 2023 [Contributors](https://github.com/trzsz/trzsz-ssh/graphs/contributors)

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
	"strings"
)

var getHostname = func() string {
	hostname, err := os.Hostname()
	if err != nil {
		warning("get hostname failed: %v", err)
		return ""
	}
	return hostname
}

func expandTokens(str string, args *sshArgs, param *loginParam, tokens string) string {
	var buf strings.Builder
	state := byte(0)
	for _, c := range str {
		if state == 0 {
			if c == '%' {
				state = '%'
				continue
			}
			buf.WriteRune(c)
			continue
		}
		state = 0
		if !strings.ContainsRune(tokens, c) {
			warning("token [%%%c] in [%s] is not supported", c, str)
			buf.WriteRune('%')
			buf.WriteRune(c)
			continue
		}
		switch c {
		case '%':
			buf.WriteRune('%')
		case 'h':
			buf.WriteString(param.host)
		case 'p':
			buf.WriteString(param.port)
		case 'r':
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
		case 'C':
			hashStr := fmt.Sprintf("%s%s%s%s", getHostname(), param.host, param.port, param.user)
			buf.WriteString(fmt.Sprintf("%x", sha1.Sum([]byte(hashStr))))
		default:
			warning("token [%%%c] in [%s] is not supported yet", c, str)
			buf.WriteRune('%')
			buf.WriteRune(c)
		}
	}
	if state != 0 {
		warning("[%s] ends with %% is invalid", str)
		buf.WriteRune('%')
	}
	return buf.String()
}

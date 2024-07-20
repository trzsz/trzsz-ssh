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
	"bytes"
	"os/exec"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
)

func getOtpCommandOutput(command, question string) string {
	argv, err := splitCommandLine(command)
	if err != nil || len(argv) == 0 {
		warning("split otp command failed: %v", err)
		return ""
	}
	var args []string
	for i, arg := range argv {
		if i > 0 && arg == "%q" {
			arg = question
		}
		debug("otp command argv[%d] = %s", i, arg)
		args = append(args, arg)
	}
	cmd := exec.Command(args[0], args[1:]...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		if errBuf.Len() > 0 {
			warning("exec otp command failed: %v, %s", err, strings.TrimSpace(errBuf.String()))
		} else {
			warning("exec otp command failed: %v", err)
		}
		return ""
	}
	if enableDebugLogging && errBuf.Len() > 0 {
		debug("otp command stderr output: %s", errBuf.String())
	}
	return strings.TrimSpace(outBuf.String())
}

func getTotpCode(secret string) string {
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		warning("generate totp code failed: %v", err)
		return ""
	}
	return code
}

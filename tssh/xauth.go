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
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

const kSshX11Proto = "MIT-MAGIC-COOKIE-1"

func getXauthAndProto(display string, trusted bool, timeout int) (string, string, error) {
	if !commandExists("xauth") {
		debug("no xauth program")
		return genFakeXauth(trusted)
	}

	if strings.HasPrefix(display, "localhost:") {
		display = "unix:" + display[10:]
	}

	var listArgs []string
	if !trusted {
		file, err := os.CreateTemp("", "xauthfile_*")
		if err != nil {
			debug("create xauth file failed: %v", err)
			return genFakeXauth(trusted)
		}
		path := file.Name()
		defer os.Remove(path)
		genArgs := []string{"-f", path, "generate", display, kSshX11Proto, "untrusted"}
		if timeout > 0 {
			genArgs = append(genArgs, "timeout", strconv.Itoa(timeout))
		}
		debug("xauth generate command: %v", genArgs)
		if _, err := execXauthCommand(genArgs); err != nil {
			debug("xauth generate failed: %v", err)
			return genFakeXauth(trusted)
		}
		listArgs = []string{"-f", path, "list", display}
	} else {
		listArgs = []string{"list", display}
	}

	debug("xauth list command: %v", listArgs)
	out, err := execXauthCommand(listArgs)
	if err != nil {
		debug("xauth list failed: %v", err)
		return genFakeXauth(trusted)
	}
	if out != "" {
		tokens := strings.Fields(out)
		if len(tokens) < 3 {
			debug("invalid xauth list output: %s", out)
			return genFakeXauth(trusted)
		}
		return tokens[2], tokens[1], nil
	}

	return genFakeXauth(trusted)
}

func execXauthCommand(args []string) (string, error) {
	cmd := exec.Command("xauth", args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		if errBuf.Len() > 0 {
			return "", fmt.Errorf("%v, %s", err, strings.TrimSpace(errBuf.String()))
		}
		return "", err
	}
	return strings.TrimSpace(outBuf.String()), nil
}

func genFakeXauth(trusted bool) (string, string, error) {
	cookie := make([]byte, 16)
	if _, err := rand.Read(cookie); err != nil {
		return "", "", fmt.Errorf("random cookie failed: %v", err)
	}
	if trusted {
		warning("No xauth data; using fake authentication data for X11 forwarding.")
	}
	return fmt.Sprintf("%x", cookie), kSshX11Proto, nil
}

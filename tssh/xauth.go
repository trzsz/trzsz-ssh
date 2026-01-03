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
		debug("X11 authentication will be faked due to xauth not found")
		return genFakeXauth()
	}

	var listArgs []string
	if !trusted {
		file, err := os.CreateTemp("", "xauthfile_*")
		if err != nil {
			warning("X11 authentication will be faked due to create temp file failed: %v", err)
			return genFakeXauth()
		}
		path := file.Name()
		_ = file.Close()
		defer func() { _ = os.Remove(path) }()
		genArgs := []string{"-f", path, "generate", display, kSshX11Proto, "untrusted"}
		if timeout > 0 {
			genArgs = append(genArgs, "timeout", strconv.Itoa(timeout))
		}
		debug("xauth generate command: %v", genArgs)
		if _, err := execXauthCommand(genArgs); err != nil {
			warning("X11 authentication will be faked due to xauth generate failed: %v", err)
			return genFakeXauth()
		}
		listArgs = []string{"-f", path, "list", display}
	} else {
		listArgs = []string{"list"}
	}

	debug("xauth list command: %v", listArgs)
	out, err := execXauthCommand(listArgs)
	if err != nil {
		warning("X11 authentication will be faked due to xauth list failed: %v", err)
		return genFakeXauth()
	}

	displayNumber := getDisplayNumber(display)
	for line := range strings.SplitSeq(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if getDisplayNumber(fields[0]) == displayNumber {
			return fields[2], fields[1], nil
		}
	}

	warning("X11 authentication will be faked due to no matching xauth for display [%s]", display)
	return genFakeXauth()
}

func getDisplayNumber(display string) string {
	if i := strings.LastIndex(display, ":"); i >= 0 {
		s := display[i+1:]
		if j := strings.IndexByte(s, '.'); j >= 0 {
			return s[:j]
		}
		return s
	}
	return display
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

func genFakeXauth() (string, string, error) {
	cookie := make([]byte, 16)
	if _, err := rand.Read(cookie); err != nil {
		return "", "", fmt.Errorf("random cookie failed: %v", err)
	}
	return fmt.Sprintf("%x", cookie), kSshX11Proto, nil
}

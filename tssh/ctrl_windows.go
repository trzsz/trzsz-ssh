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
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

func getRealPath(path string) string {
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return path
	}
	return realPath
}

// getOpenSSH returns a usable OpenSSH binary path and its (major, minor) version.
// It tries hard to avoid returning the current program path (e.g. when tssh is
// installed as "ssh" in PATH).
func getOpenSSH() (string, int, int, error) {
	tsshPath, err := os.Executable()
	if err != nil {
		return "", 0, 0, err
	}

	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		return "", 0, 0, err
	}
	if getRealPath(sshPath) == getRealPath(tsshPath) {
		return "", 0, 0, fmt.Errorf("no usable ssh found")
	}

	out, err := exec.Command(sshPath, "-V").CombinedOutput()
	if err != nil {
		return "", 0, 0, err
	}
	re := regexp.MustCompile(`OpenSSH_(\d+)\.(\d+)`)
	matches := re.FindStringSubmatch(string(out))
	majorVersion := -1
	minorVersion := -1
	if len(matches) > 2 {
		if v, err := strconv.ParseUint(matches[1], 10, 32); err == nil {
			majorVersion = int(v)
		}
		if v, err := strconv.ParseUint(matches[2], 10, 32); err == nil {
			minorVersion = int(v)
		}
	}
	return sshPath, majorVersion, minorVersion, nil
}

func connectViaControl(param *sshParam) SshClient {
	ctrlMaster := getOptionConfig(param.args, "ControlMaster")
	ctrlPath := getOptionConfig(param.args, "ControlPath")

	switch strings.ToLower(ctrlMaster) {
	case "auto", "yes", "ask", "autoask":
		warning("ControlMaster is not supported on Windows")
	}

	switch strings.ToLower(ctrlPath) {
	case "", "none":
		return nil
	}

	warning("ControlPath is not supported on Windows")
	return nil
}

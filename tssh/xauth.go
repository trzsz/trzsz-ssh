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
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/trzsz/ssh_config"
)

const kSshX11Proto = "MIT-MAGIC-COOKIE-1"

const kSshX11TimeoutSlack = 60

type xauthInfo struct {
	xauthProto string
	realCookie []byte
	fakeCookie []byte
}

func getXauthInfo(args *sshArgs, display string, trusted bool, timeout uint32) (*xauthInfo, error) {
	xauthData, err := genListXauthInfo(args, display, trusted, timeout)
	if err == nil {
		return xauthData, nil
	}

	if trusted || runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		// === Trusted-mode fallback ===
		// In trusted mode, if authentication cookie cannot be obtained via xauth list,
		// a fake cookie is generated. The X11 server will ignore it and use whatever
		// authentication mechanisms it was using otherwise for the local connection.
		//
		// === Platform-specific fallback ===
		// On Windows or macOS, using a fake cookie is relatively safe because the risk is
		// limited to the X11 server application. The remote X11 client cannot normally
		// capture input or events from other local applications outside that X11 server.
		if isRunningInRemoteSsh() {
			warning("using fake authentication cookie for X11 forwarding due to: %v", err)
		} else {
			debug("using fake authentication cookie for X11 forwarding due to: %v", err)
		}
		return fillFakeCookie(&xauthInfo{xauthProto: kSshX11Proto})
	}

	// Don't fall back to fake cookie for untrusted forwarding on Linux.
	return nil, err
}

func genListXauthInfo(args *sshArgs, display string, trusted bool, timeout uint32) (*xauthInfo, error) {
	xauthPath := getXauthPath(args)
	if xauthPath == "" {
		return nil, fmt.Errorf("no xauth program")
	}

	if strings.HasPrefix(display, "/") {
		if pos := strings.LastIndexByte(display, ':'); pos > 0 {
			display = "unix" + display[pos:]
		}
	} else if strings.HasPrefix(display, "localhost:") {
		display = "unix" + display[9:]
	}

	var genPath string
	if !trusted {
		file, err := os.CreateTemp("", "xauthfile_*")
		if err != nil {
			return nil, fmt.Errorf("create temp file failed: %v", err)
		}
		genPath = file.Name()
		_ = file.Close()
		defer func() { _ = os.Remove(genPath) }()
		genArgs := []string{"-f", genPath, "generate", display, kSshX11Proto, "untrusted"}
		if timeout > 0 {
			genArgs = append(genArgs, "timeout", strconv.FormatUint(uint64(getX11Timeout(timeout)), 10))
		}
		debug("xauth generate command: %s %v", xauthPath, genArgs)
		if _, err := execXauthCommand(xauthPath, genArgs); err != nil {
			return nil, fmt.Errorf("xauth generate failed: %v", err)
		}
	}

	listArgs := []string{"-q", "-n"}
	if genPath != "" {
		listArgs = append(listArgs, "-f", genPath)
	}
	listArgs = append(listArgs, "list", display)
	debug("xauth list command: %s %v", xauthPath, listArgs)
	out, err := execXauthCommand(xauthPath, listArgs)
	if err != nil {
		return nil, fmt.Errorf("xauth list failed: %v", err)
	}

	for line := range strings.SplitSeq(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		// display already constrained, just return the first one.
		cookie, err := hex.DecodeString(fields[2])
		if err != nil {
			return nil, fmt.Errorf("decode cookie [%s] failed: %v", fields[2], err)
		}
		return fillFakeCookie(&xauthInfo{xauthProto: fields[1], realCookie: cookie})
	}

	return nil, fmt.Errorf("no matching xauth for display: %s", display)
}

func getXauthPath(args *sshArgs) string {
	ssh_config.SetDefault("XAuthLocation", "")
	xauthPath := getOptionConfig(args, "XAuthLocation")
	if xauthPath != "" {
		if isFileExist(xauthPath) {
			return xauthPath
		} else {
			warning("XAuthLocation [%s] not found, falling back to xauth in $PATH", xauthPath)
		}
	}

	if !commandExists("xauth") {
		return ""
	}

	return "xauth"
}

func execXauthCommand(xauthPath string, args []string) (string, error) {
	cmd := exec.Command(xauthPath, args...)
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

func getX11Timeout(timeout uint32) uint32 {
	if timeout < math.MaxUint32-kSshX11TimeoutSlack {
		return uint32(timeout) + kSshX11TimeoutSlack
	}
	return math.MaxUint32
}

func fillFakeCookie(xauthData *xauthInfo) (*xauthInfo, error) {
	length := len(xauthData.realCookie)
	if length == 0 {
		length = 16
	}
	cookie := make([]byte, length)
	if _, err := rand.Read(cookie); err != nil {
		return nil, fmt.Errorf("random cookie failed: %v", err)
	}
	xauthData.fakeCookie = cookie
	if len(xauthData.realCookie) == 0 {
		xauthData.realCookie = cookie
	}
	return xauthData, nil
}

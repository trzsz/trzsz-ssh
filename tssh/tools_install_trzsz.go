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
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const kMaxBufferSize = 32 * 1024

const (
	kScpOK    = 0
	kScpWarn  = 1
	kScpError = 2
)

type trzszRelease struct {
	TagName string `json:"tag_name"`
}

func getLatestTrzszVersion() (string, error) {
	resp, err := http.Get("https://api.github.com/repos/trzsz/trzsz-go/releases/latest")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("http response status code %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var release trzszRelease
	if err := json.Unmarshal(body, &release); err != nil {
		return "", err
	}
	return release.TagName[1:], nil
}

func checkTrzszVersion(client SshClient, cmd, name, version string) bool {
	session, err := client.NewSession()
	if err != nil {
		return false
	}
	defer session.Close()
	output, err := session.CombinedOutput(cmd)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(output)) == fmt.Sprintf("%s (trzsz) go %s", name, version)
}

func pathJoin(path, name string) string {
	// local may be Windows, remote may be Linux, so filepath.Join is not suitable here.
	if strings.HasSuffix(path, "/") {
		return path + name
	}
	return fmt.Sprintf("%s/%s", path, name)
}

func checkInstalledVersion(client SshClient, path, name, version string) bool {
	cmd := fmt.Sprintf("%s -v", pathJoin(path, name))
	return checkTrzszVersion(client, cmd, name, version)
}

func checkTrzszExecutable(client SshClient, name, version string) bool {
	return checkTrzszVersion(client, fmt.Sprintf("$SHELL -l -c '%s -v'", name), name, version)
}

func checkTrzszPathEnv(client SshClient, version, path string) {
	trzExecutable := checkTrzszExecutable(client, "trz", version)
	tszExecutable := checkTrzszExecutable(client, "tsz", version)
	if !trzExecutable || !tszExecutable {
		toolsInfo("InstallTrzsz", "you may need to add %s to the PATH environment variable", path)
	}
}

func getRemoteUserHome(client SshClient) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	output, err := session.Output("env")
	if err != nil {
		return "", err
	}
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		env := scanner.Text()
		pos := strings.IndexRune(env, '=')
		if pos <= 0 {
			continue
		}
		if env[:pos] == "HOME" {
			if home := strings.TrimSpace(env[pos+1:]); home != "" {
				return home, nil
			}
			break
		}
	}
	return "~", nil
}

func getRemoteServerOS(client SshClient) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	output, err := session.Output("uname -s")
	if err != nil {
		return "", err
	}
	name := strings.TrimSpace(string(output))
	switch strings.ToLower(name) {
	case "darwin":
		return "macos", nil
	case "linux":
		return "linux", nil
	default:
		return "", fmt.Errorf("os [%s] is not support yet", name)
	}
}

func getRemoteServerArch(client SshClient) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	output, err := session.Output("uname -m")
	if err != nil {
		return "", err
	}
	arch := strings.TrimSpace(string(output))
	switch strings.ToLower(arch) {
	case "x86_64":
		return "x86_64", nil
	case "aarch64":
		return "aarch64", nil
	case "armv6l":
		return "armv6", nil
	case "armv7l", "armv7hl":
		return "armv7", nil
	case "i386", "i486", "i586", "i686":
		return "i386", nil
	default:
		return "", fmt.Errorf("arch [%s] is not support yet", arch)
	}
}

func mkdirInstallPath(client SshClient, path string) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	output, err := session.CombinedOutput(fmt.Sprintf("mkdir -p -m 755 %s", path))
	if err != nil {
		errMsg := string(bytes.TrimSpace(output))
		if errMsg != "" {
			return fmt.Errorf("%s", errMsg)
		}
		return err
	}
	return nil
}

func extractTrzszBinary(gzr io.Reader, version, svrOS, arch string) ([]byte, []byte, error) {
	pkgName := fmt.Sprintf("trzsz_%s_%s_%s", version, svrOS, arch)
	var trz, tsz bytes.Buffer
	tarReader := tar.NewReader(gzr)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		if header.Typeflag == tar.TypeDir {
			if header.Name != pkgName {
				return nil, nil, fmt.Errorf("package [%s] does not match [%s]", header.Name, pkgName)
			}
			continue
		}
		switch header.Name {
		case pkgName + "/trz":
			if _, err := io.Copy(&trz, tarReader); err != nil {
				return nil, nil, err
			}
		case pkgName + "/tsz":
			if _, err := io.Copy(&tsz, tarReader); err != nil {
				return nil, nil, err
			}
		case pkgName + "/trzsz":
			continue
		default:
			if strings.HasPrefix(header.Name, "trzsz_") {
				switch filepath.Base(header.Name) {
				case "trz", "tsz", "trzsz":
					return nil, nil, fmt.Errorf("package [%s] does not match [%s]", filepath.Dir(header.Name), pkgName)
				}
			}
			return nil, nil, fmt.Errorf("package contains unexpected files: %s", header.Name)
		}
	}
	if trz.Len() == 0 {
		return nil, nil, fmt.Errorf("can't find trz binary in the package")
	}
	if tsz.Len() == 0 {
		return nil, nil, fmt.Errorf("can't find tsz binary in the package")
	}
	return trz.Bytes(), tsz.Bytes(), nil
}

func downloadTrzszBinary(version, svrOS, arch string) ([]byte, []byte, error) {
	url := fmt.Sprintf("https://github.com/trzsz/trzsz-go/releases/download/v%s/trzsz_%s_%s_%s.tar.gz",
		version, version, svrOS, arch)
	toolsInfo("InstallTrzsz", "download url: %s", url)

	resp, err := http.Get(url)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("http response status code %d", resp.StatusCode)
	}

	contentLength := int(resp.ContentLength)
	progress := newToolsProgress("InstallTrzsz", "download percentage", contentLength)
	defer progress.stopProgress()

	buffer := make([]byte, contentLength)
	currentStep := 0
	for currentStep < contentLength {
		maxBufferIdx := currentStep + kMaxBufferSize
		if maxBufferIdx > contentLength {
			maxBufferIdx = contentLength
		}
		n, err := resp.Body.Read(buffer[currentStep:maxBufferIdx])
		if err != nil {
			return nil, nil, err
		}
		currentStep += n
		progress.addStep(n)
	}

	gzr, err := gzip.NewReader(bytes.NewReader(buffer))
	if err != nil {
		return nil, nil, err
	}
	defer gzr.Close()

	return extractTrzszBinary(gzr, version, svrOS, arch)
}

func readTrzszBinary(path, version, svrOS, arch string) ([]byte, []byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	gzr, err := gzip.NewReader(file)
	if err != nil {
		return nil, nil, err
	}
	defer gzr.Close()

	return extractTrzszBinary(gzr, version, svrOS, arch)
}

func uploadTrzszBinary(client SshClient, path string, trz, tsz []byte) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	writer, err := session.StdinPipe()
	if err != nil {
		return err
	}
	reader, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	progress := newToolsProgress("InstallTrzsz", "upload percentage", len(trz)+len(tsz))

	var errMsg []string
	checkTransferResponse := func() bool {
		buf := make([]byte, 1)
		n, err := reader.Read(buf)
		if err != nil || n != 1 {
			return false
		}
		switch buf[0] {
		case kScpOK:
			return true
		case kScpWarn, kScpError:
			msg, _ := bufio.NewReader(reader).ReadString('\n')
			errMsg = append(errMsg, fmt.Sprintf("scp response [%d]: %s", buf[0], strings.TrimSpace(msg)))
			return false
		default:
			errMsg = append(errMsg, fmt.Sprintf("unknown scp response [%d]", buf[0]))
			return false
		}
	}
	writeTransferCommand := func(cmd string) bool {
		if n, err := writer.Write([]byte(cmd)); err != nil || n != len(cmd) {
			return false
		}
		return checkTransferResponse()
	}
	writeBinaryContent := func(buf []byte) bool {
		currentStep := 0
		for currentStep < len(buf) {
			maxBufferIdx := currentStep + kMaxBufferSize
			if maxBufferIdx > len(buf) {
				maxBufferIdx = len(buf)
			}
			n, err := writer.Write(buf[currentStep:maxBufferIdx])
			if err != nil {
				return false
			}
			currentStep += n
			// add is better than update, since the total size is `len(trz) + len(tsz)`.
			progress.addStep(n)
		}
		return writeTransferCommand("\x00")
	}

	go func() {
		defer progress.stopProgress()
		if !checkTransferResponse() {
			return
		}
		if !writeTransferCommand(fmt.Sprintf("C0755 %d trz\n", len(trz))) {
			return
		}
		if !writeBinaryContent(trz) {
			return
		}
		if !writeTransferCommand(fmt.Sprintf("C0755 %d tsz\n", len(tsz))) {
			return
		}
		if !writeBinaryContent(tsz) {
			return
		}
		_ = writeTransferCommand("E\n")
	}()

	stderr, err := session.StderrPipe()
	if err != nil {
		return err
	}
	if err := session.Run(fmt.Sprintf("scp -tqr %s", path)); err != nil {
		msg := readFromStream(stderr)
		if msg != "" {
			errMsg = append(errMsg, msg)
		}
		if len(errMsg) > 0 {
			return fmt.Errorf("%s", strings.Join(errMsg, ", "))
		}
		return err
	}
	return nil
}

func execInstallTrzsz(args *sshArgs, client SshClient) {
	version := args.TrzszVersion
	if version == "" {
		var err error
		if version, err = getLatestTrzszVersion(); err != nil {
			toolsWarn("InstallTrzsz", "get latest trzsz version failed: %v", err)
			toolsInfo("InstallTrzsz", "you can specify the version of trzsz through --trzsz-version")
			return
		}
	}

	installPath := args.InstallPath
	if installPath == "" {
		installPath = "~/.local/bin/"
	}

	if strings.HasPrefix(installPath, "~/") {
		home, err := getRemoteUserHome(client)
		if err != nil {
			toolsWarn("InstallTrzsz", "get remote user home path failed: %v", err)
		} else {
			installPath = pathJoin(home, installPath[2:])
		}
	}

	trzInstalled := checkInstalledVersion(client, installPath, "trz", version)
	tszInstalled := checkInstalledVersion(client, installPath, "tsz", version)
	if trzInstalled && tszInstalled {
		toolsSucc("InstallTrzsz", "trzsz %s has been installed in %s", version, installPath)
		checkTrzszPathEnv(client, version, installPath)
		return
	}

	svrOS, err := getRemoteServerOS(client)
	if err != nil {
		toolsWarn("InstallTrzsz", "get remote server operating system failed: %v", err)
		return
	}

	arch, err := getRemoteServerArch(client)
	if err != nil {
		toolsWarn("InstallTrzsz", "get remote server cpu architecture failed: %v", err)
		return
	}

	if err := mkdirInstallPath(client, installPath); err != nil {
		toolsWarn("InstallTrzsz", "mkdir [%s] failed: %v", installPath, err)
		return
	}

	var trz, tsz []byte
	if args.TrzszBinPath != "" {
		trz, tsz, err = readTrzszBinary(args.TrzszBinPath, version, svrOS, arch)
		if err != nil {
			toolsWarn("InstallTrzsz", "extract installation files failed: %v", err)
			return
		}
	} else {
		trz, tsz, err = downloadTrzszBinary(version, svrOS, arch)
		if err != nil {
			toolsWarn("InstallTrzsz", "download installation files failed: %v", err)
			toolsInfo("InstallTrzsz", "you can download the release from github and specify it with --trzsz-bin-path")
			return
		}
	}

	if err := uploadTrzszBinary(client, installPath, trz, tsz); err != nil {
		toolsWarn("InstallTrzsz", "upload trzsz binary files failed: %v", err)
		return
	}

	toolsSucc("InstallTrzsz", "trzsz %s installation to %s completed successfully", version, installPath)
	checkTrzszPathEnv(client, version, installPath)
}

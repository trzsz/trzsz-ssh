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
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/skeema/knownhosts"
	"golang.org/x/crypto/ssh"
	xkh "golang.org/x/crypto/ssh/knownhosts"
)

var acceptHostKeys []string
var acceptHostKeyMu sync.Mutex
var addHostKeyMutex sync.Mutex
var sshLoginSuccess atomic.Bool

type malformedKnownHost struct {
	path   string
	line   int
	reason string
}

type knownHostsSnapshot struct {
	originalPath  string
	temporaryPath string
	lines         [][]byte
}

func createKnownHostsSnapshots(files []string) ([]*knownHostsSnapshot, error) {
	snapshots := make([]*knownHostsSnapshot, 0, len(files))
	cleanup := func() {
		for _, snapshot := range snapshots {
			_ = os.Remove(snapshot.temporaryPath)
		}
	}

	for _, path := range files {
		input, err := os.ReadFile(path)
		if err != nil {
			cleanup()
			return nil, err
		}

		file, err := os.CreateTemp("", "tssh_known_hosts_*")
		if err != nil {
			cleanup()
			return nil, err
		}
		temporaryPath := file.Name()
		if err := writeAll(file, input); err != nil {
			_ = file.Close()
			_ = os.Remove(temporaryPath)
			cleanup()
			return nil, err
		}
		if err := file.Close(); err != nil {
			_ = os.Remove(temporaryPath)
			cleanup()
			return nil, err
		}

		snapshots = append(snapshots, &knownHostsSnapshot{
			originalPath:  path,
			temporaryPath: temporaryPath,
			lines:         bytes.Split(input, []byte{'\n'}),
		})
	}
	return snapshots, nil
}

func parseKnownHostsLineError(err error, snapshots []*knownHostsSnapshot) (*knownHostsSnapshot, int, string, bool) {
	message := err.Error()
	for _, snapshot := range snapshots {
		prefix := "knownhosts: " + snapshot.temporaryPath + ":"
		if !strings.HasPrefix(message, prefix) {
			continue
		}
		remainder := strings.TrimPrefix(message, prefix)
		lineText, reason, ok := strings.Cut(remainder, ":")
		if !ok {
			return nil, 0, "", false
		}
		line, parseErr := strconv.Atoi(lineText)
		if parseErr != nil || line < 1 || line > len(snapshot.lines) {
			return nil, 0, "", false
		}
		return snapshot, line, strings.TrimSpace(reason), true
	}
	return nil, 0, "", false
}

func rewriteKnownHostsSnapshot(snapshot *knownHostsSnapshot) error {
	return os.WriteFile(snapshot.temporaryPath, bytes.Join(snapshot.lines, []byte{'\n'}), 0600)
}

func restoreKnownHostsPaths(err error, snapshots []*knownHostsSnapshot) error {
	message := err.Error()
	for _, snapshot := range snapshots {
		message = strings.ReplaceAll(message, snapshot.temporaryPath, snapshot.originalPath)
	}
	return errors.New(message)
}

func newKnownHostsDB(files ...string) (*knownhosts.HostKeyDB, []malformedKnownHost, error) {
	db, err := knownhosts.NewDB(files...)
	if err == nil {
		return db, nil, nil
	}

	snapshots, snapshotErr := createKnownHostsSnapshots(files)
	if snapshotErr != nil {
		return nil, nil, snapshotErr
	}
	defer func() {
		for _, snapshot := range snapshots {
			_ = os.Remove(snapshot.temporaryPath)
		}
	}()

	temporaryFiles := make([]string, 0, len(snapshots))
	for _, snapshot := range snapshots {
		temporaryFiles = append(temporaryFiles, snapshot.temporaryPath)
	}

	var malformed []malformedKnownHost
	for {
		db, err = knownhosts.NewDB(temporaryFiles...)
		if err == nil {
			return db, malformed, nil
		}

		snapshot, line, reason, ok := parseKnownHostsLineError(err, snapshots)
		if !ok {
			return nil, nil, restoreKnownHostsPaths(err, snapshots)
		}
		snapshot.lines[line-1] = nil
		if err := rewriteKnownHostsSnapshot(snapshot); err != nil {
			return nil, nil, err
		}
		malformed = append(malformed, malformedKnownHost{
			path:   snapshot.originalPath,
			line:   line,
			reason: reason,
		})
	}
}

func isAcceptedHostKey(keyNormalizedLine string) bool {
	acceptHostKeyMu.Lock()
	defer acceptHostKeyMu.Unlock()
	return slices.Contains(acceptHostKeys, keyNormalizedLine)
}

func addAcceptedHostKey(keyNormalizedLine string) {
	acceptHostKeyMu.Lock()
	defer acceptHostKeyMu.Unlock()
	acceptHostKeys = append(acceptHostKeys, keyNormalizedLine)
}

func ensureNewline(file *os.File) error {
	if _, err := file.Seek(-1, io.SeekEnd); err != nil {
		return nil
	}
	buf := make([]byte, 1)
	if n, err := file.Read(buf); err != nil || n != 1 || buf[0] == '\n' {
		return nil
	}
	if _, err := file.Write([]byte("\n")); err != nil {
		return err
	}
	return nil
}

func writeKnownHost(args *sshArgs, path, host string, key ssh.PublicKey) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	if err := ensureNewline(file); err != nil {
		return err
	}

	hostNormalized := knownhosts.Normalize(host)
	if strings.ContainsAny(hostNormalized, "\t ") {
		return fmt.Errorf("host '%s' contains spaces", hostNormalized)
	}

	address := hostNormalized
	if strings.EqualFold(getOptionConfig(args, "HashKnownHosts"), "yes") {
		address = xkh.HashHostname(hostNormalized)
	}

	line := knownhosts.Line([]string{address}, key) + "\n"
	return writeAll(file, []byte(line))
}

func addHostKey(args *sshArgs, path, host string, key ssh.PublicKey, ask bool, dnsHint string) error {
	addHostKeyMutex.Lock()
	defer addHostKeyMutex.Unlock()

	if sshLoginSuccess.Load() {
		warning("The public key of the remote server has changed after login")
		return fmt.Errorf("host key changed")
	}

	// writing only during the login process with the user's permission
	if ask {
		fingerprint := ssh.FingerprintSHA256(key)
		fmt.Fprintf(os.Stderr, "The authenticity of host '%s' can't be established.\r\n"+
			"%s key fingerprint is %s.\r\n", host, shortKeyType(key.Type()), fingerprint)
		if dnsHint != "" {
			fmt.Fprintf(os.Stderr, "%s\r\n", dnsHint)
		}

		stdin, closer, err := getKeyboardInput()
		if err != nil {
			return err
		}
		defer closer()

		reader := bufio.NewReader(stdin)
		_, _ = os.Stderr.WriteString("Are you sure you want to continue connecting (yes/no/[fingerprint])? ")
		for {
			input, err := reader.ReadString('\n')
			if err != nil {
				return err
			}
			input = strings.TrimSpace(input)
			if input == fingerprint {
				break
			}
			if strings.EqualFold(input, "yes") {
				break
			} else if strings.EqualFold(input, "no") {
				return fmt.Errorf("host key not trusted")
			}
			_, _ = os.Stderr.WriteString("Please type 'yes', 'no' or the fingerprint: ")
		}
	}

	if err := writeKnownHost(args, path, host, key); err != nil {
		warning("Failed to add the host to the list of known hosts (%s): %v", path, err)
		return nil
	}

	warning("Permanently added '%s' (%s) to the list of known hosts.", host, shortKeyType(key.Type()))
	return nil
}

func getHostKeyCallback(param *sshParam) (ssh.HostKeyCallback, []string, error) {
	var files []string
	addKnownHostsFiles := func(key string, user bool, defaults []string) error {
		knownHostsFiles := getOptionConfigSplits(param.args, key)
		if len(knownHostsFiles) == 0 {
			if enableDebugLogging {
				debug("%s not configured, using default: %s", key, strings.Join(defaults, ", "))
			}
			knownHostsFiles = defaults
		}
		if len(knownHostsFiles) == 1 && strings.EqualFold(knownHostsFiles[0], "none") {
			debug("%s disabled (set to 'none')", key)
			return nil
		}
		for _, path := range knownHostsFiles {
			var resolvedPath string
			if user {
				expandedPath, err := expandTokens(path, param, "%CdhijkLlnpru")
				if err != nil {
					return fmt.Errorf("expand UserKnownHostsFile [%s] failed: %v", path, err)
				}
				resolvedPath = resolveHomeDir(expandedPath)
			} else {
				resolvedPath = path
			}
			if !isFileExist(resolvedPath) {
				debug("%s [%s] does not exist", key, resolvedPath)
				continue
			}
			if !canReadFile(resolvedPath) {
				if user {
					warning("%s [%s] can't be read", key, resolvedPath)
				} else {
					debug("%s [%s] can't be read", key, resolvedPath)
				}
				continue
			}
			debug("add %s: %s", key, resolvedPath)
			files = append(files, resolvedPath)
		}
		return nil
	}

	if err := addKnownHostsFiles("UserKnownHostsFile", true, []string{"~/.ssh/known_hosts", "~/.ssh/known_hosts2"}); err != nil {
		return nil, nil, err
	}

	primaryPath := ""
	if len(files) > 0 {
		primaryPath = files[0]
		if param.args.RemoveHostKey {
			for _, path := range files {
				if err := removeHostKey(path, param); err != nil {
					warning("remove host key failed: %v", err)
				}
			}
		}
	}

	if err := addKnownHostsFiles("GlobalKnownHostsFile", false, []string{"/etc/ssh/ssh_known_hosts", "/etc/ssh/ssh_known_hosts2"}); err != nil {
		return nil, nil, err
	}

	khdb, malformed, err := newKnownHostsDB(files...)
	if err != nil {
		return nil, nil, fmt.Errorf("new knownhosts failed: %v", err)
	}
	for _, entry := range malformed {
		warning("Ignoring malformed known_hosts entry %s:%d: %s", entry.path, entry.line, entry.reason)
	}

	hostKeyCallback := func(host string, remote net.Addr, key ssh.PublicKey) (err error) {
		keyNormalizedLine := knownhosts.Line([]string{host}, key)
		if isAcceptedHostKey(keyNormalizedLine) {
			if enableDebugLogging {
				debug("host key [%s] has been accepted", ssh.FingerprintSHA256(key))
			}
			return nil
		}

		defer func() {
			if err == nil {
				addAcceptedHostKey(keyNormalizedLine)
			}
		}()

		err = khdb.HostKeyCallback()(host, remote, key)
		if err == nil {
			return nil
		}

		var dnsHint string
		if verifyDNS := getOptionConfig(param.args, "VerifyHostKeyDNS"); strings.EqualFold(verifyDNS, "yes") ||
			strings.EqualFold(verifyDNS, "true") || strings.EqualFold(verifyDNS, "ask") {
			dnsHint = "\033[0;33mNo matching host key fingerprint found in DNS.\033[0m"
			found, matched, authenticate, err := verifyHostKeyDNS(host, key)
			if err != nil {
				warning("Verify host key DNS failed: %v", err)
			} else if found {
				if (strings.EqualFold(verifyDNS, "yes") || strings.EqualFold(verifyDNS, "true")) && matched && authenticate() {
					debug("DNSSEC-validated host key fingerprint found in DNS for '%s'", host)
					return nil
				}
				if matched {
					dnsHint = "\033[0;32mMatching host key fingerprint found in DNS.\033[0m"
				} else {
					warnChangedKey(key)
					fmt.Fprintf(os.Stderr, "Update the SSHFP RR in DNS with the new host key to get rid of this message.\r\n")
				}
			}
		}

		strictHostKeyChecking := strings.ToLower(getOptionConfig(param.args, "StrictHostKeyChecking"))
		if knownhosts.IsHostKeyChanged(err) {
			path := primaryPath
			if path == "" {
				path = "~/.ssh/known_hosts"
			}
			warnChangedKey(key)
			fmt.Fprintf(os.Stderr, "Add correct host key in %s to get rid of this message.\r\n", path)
			if primaryPath != "" {
				dest := param.args.originalDest
				if dest == "" {
					dest = param.args.Destination
				}
				port := ""
				if param.args.Port != 0 {
					port = fmt.Sprintf("-p %d ", param.args.Port)
				}
				fmt.Fprintf(os.Stderr, "Or reconnect with:\r\n  tssh --remove-host-key %s%s\r\n", port, dest)
			}
		} else if knownhosts.IsHostUnknown(err) && primaryPath != "" {
			ask := true
			switch strictHostKeyChecking {
			case "yes", "true":
				return err
			case "accept-new", "no", "off", "false":
				ask = false
			}
			return addHostKey(param.args, primaryPath, host, key, ask, dnsHint)
		}
		switch strictHostKeyChecking {
		case "no", "off", "false":
			return nil
		default:
			return err
		}
	}

	return hostKeyCallback, khdb.HostKeyAlgorithms(param.addr), err
}

func warnChangedKey(key ssh.PublicKey) {
	fmt.Fprintf(os.Stderr, "\033[0;31m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n"+
		"@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\r\n"+
		"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n"+
		"IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\r\n"+
		"Someone could be eavesdropping on you right now (man-in-the-middle attack)!\033[0m\r\n"+
		"It is also possible that a host key has just been changed.\r\n"+
		"The fingerprint for the %s key sent by the remote host is\r\n"+
		"%s\r\n"+
		"Please contact your system administrator.\r\n",
		shortKeyType(key.Type()), ssh.FingerprintSHA256(key))
}

func removeHostKey(path string, param *sshParam) error {
	input, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read known_hosts %q failed: %v", path, err)
	}

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat known_hosts %q failed: %v", path, err)
	}
	filePerm := info.Mode().Perm()

	normalizedTarget := knownhosts.Normalize(param.addr)

	inputLines := bytes.Split(input, []byte{'\n'})
	outputLines := make([][]byte, 0, len(inputLines))
	removedCount := 0

	for _, line := range inputLines {
		trimedLine := bytes.TrimSpace(line)
		if len(trimedLine) == 0 || trimedLine[0] == '#' {
			outputLines = append(outputLines, line)
			continue
		}

		fields := bytes.Fields(trimedLine)
		if len(fields) == 0 {
			outputLines = append(outputLines, line)
			continue
		}

		hostField := string(fields[0])
		if strings.HasPrefix(hostField, "@") && len(fields) > 1 {
			hostField = string(fields[1])
		}

		if matchKnownHosts(hostField, normalizedTarget) {
			removedCount++
			continue
		}

		outputLines = append(outputLines, line)
	}

	if removedCount == 0 {
		fmt.Fprintf(os.Stderr, "\033[0;36mNo host keys found for %s in %s\033[0m\r\n", normalizedTarget, path)
		return nil
	}

	backupPath := path + ".old"
	if err := os.WriteFile(backupPath, input, filePerm); err != nil {
		return fmt.Errorf("create backup %q failed: %v", backupPath, err)
	}

	if err := os.WriteFile(path, bytes.Join(outputLines, []byte{'\n'}), filePerm); err != nil {
		return fmt.Errorf("update known_hosts %q failed: %v", path, err)
	}

	fmt.Fprintf(os.Stderr, "\033[0;36mRemoved %d outdated key(s) for %s from %s (backup saved to %s)\033[0m\r\n",
		removedCount, normalizedTarget, path, backupPath)
	return nil
}

func matchKnownHosts(hosts string, target string) bool {
	parts := strings.Split(hosts, ",")
	for _, part := range parts {
		if strings.HasPrefix(part, "|1|") {
			if matchHashed(part, target) {
				return true
			}
			continue
		}
		if strings.EqualFold(part, target) {
			return true
		}
	}
	return false
}

func matchHashed(hashedPart string, target string) bool {
	subParts := strings.Split(hashedPart, "|")
	if len(subParts) < 4 {
		return false
	}
	saltB64 := subParts[2]
	hashB64 := subParts[3]

	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return false
	}
	expectedHash, err := base64.StdEncoding.DecodeString(hashB64)
	if err != nil {
		return false
	}

	mac := hmac.New(sha1.New, salt)
	mac.Write([]byte(target))
	computedHash := mac.Sum(nil)

	return hmac.Equal(computedHash, expectedHash)
}

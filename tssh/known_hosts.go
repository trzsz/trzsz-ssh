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
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/skeema/knownhosts"
	"golang.org/x/crypto/ssh"
)

var acceptHostKeys []string
var acceptHostKeyMu sync.Mutex
var addHostKeyMutex sync.Mutex
var sshLoginSuccess atomic.Bool

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

func writeKnownHost(path, host string, key ssh.PublicKey) error {
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
	line := knownhosts.Line([]string{hostNormalized}, key) + "\n"
	return writeAll(file, []byte(line))
}

func addHostKey(path, host string, key ssh.PublicKey, ask bool, dnsHint string) error {
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
			input = strings.ToLower(input)
			if input == "yes" {
				break
			} else if input == "no" {
				return fmt.Errorf("host key not trusted")
			}
			_, _ = os.Stderr.WriteString("Please type 'yes', 'no' or the fingerprint: ")
		}
	}

	if err := writeKnownHost(path, host, key); err != nil {
		warning("Failed to add the host to the list of known hosts (%s): %v", path, err)
		return nil
	}

	warning("Permanently added '%s' (%s) to the list of known hosts.", host, shortKeyType(key.Type()))
	return nil
}

func getHostKeyCallback(param *sshParam) (ssh.HostKeyCallback, []string, error) {
	primaryPath := ""
	var files []string
	addKnownHostsFiles := func(key string, user bool, defaults []string) error {
		knownHostsFiles := getOptionConfigSplits(param.args, key)
		if len(knownHostsFiles) == 0 {
			if enableDebugLogging {
				debug("%s not configured, using default: %s", key, strings.Join(defaults, ", "))
			}
			knownHostsFiles = defaults
		}
		if len(knownHostsFiles) == 1 && strings.ToLower(knownHostsFiles[0]) == "none" {
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
				if primaryPath == "" {
					primaryPath = resolvedPath
				}
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
	if err := addKnownHostsFiles("GlobalKnownHostsFile", false, []string{"/etc/ssh/ssh_known_hosts", "/etc/ssh/ssh_known_hosts2"}); err != nil {
		return nil, nil, err
	}

	khdb, err := knownhosts.NewDB(files...)
	if err != nil {
		return nil, nil, fmt.Errorf("new knownhosts failed: %v", err)
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
		verifyDNS := strings.ToLower(getOptionConfig(param.args, "VerifyHostKeyDNS"))
		if verifyDNS == "yes" || verifyDNS == "true" || verifyDNS == "ask" {
			dnsHint = "\033[0;33mNo matching host key fingerprint found in DNS.\033[0m"
			found, matched, authenticate, err := verifyHostKeyDNS(host, key)
			if err != nil {
				warning("Verify host key DNS failed: %v", err)
			} else if found {
				if (verifyDNS == "yes" || verifyDNS == "true") && matched && authenticate() {
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
		} else if knownhosts.IsHostUnknown(err) && primaryPath != "" {
			ask := true
			switch strictHostKeyChecking {
			case "yes", "true":
				return err
			case "accept-new", "no", "off", "false":
				ask = false
			}
			return addHostKey(primaryPath, host, key, ask, dnsHint)
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

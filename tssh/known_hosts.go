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
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/skeema/knownhosts"
	"golang.org/x/crypto/ssh"
)

var acceptHostKeys []string
var sshLoginSuccess atomic.Bool

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

func addHostKey(path, host string, key ssh.PublicKey, ask bool) error {
	keyNormalizedLine := knownhosts.Line([]string{host}, key)
	if slices.Contains(acceptHostKeys, keyNormalizedLine) {
		return nil
	}

	if ask {
		if sshLoginSuccess.Load() {
			fmt.Fprintf(os.Stderr, "\r\n\033[0;31mThe public key of the remote server has changed after login.\033[0m\r\n")
			return fmt.Errorf("host key changed")
		}

		fingerprint := ssh.FingerprintSHA256(key)
		fmt.Fprintf(os.Stderr, "The authenticity of host '%s' can't be established.\r\n"+
			"%s key fingerprint is %s.\r\n", host, key.Type(), fingerprint)

		stdin, closer, err := getKeyboardInput()
		if err != nil {
			return err
		}
		defer closer()

		reader := bufio.NewReader(stdin)
		fmt.Fprintf(os.Stderr, "Are you sure you want to continue connecting (yes/no/[fingerprint])? ")
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
			fmt.Fprintf(os.Stderr, "Please type 'yes', 'no' or the fingerprint: ")
		}
	}

	acceptHostKeys = append(acceptHostKeys, keyNormalizedLine)

	if err := writeKnownHost(path, host, key); err != nil {
		warning("Failed to add the host to the list of known hosts (%s): %v", path, err)
		return nil
	}

	warning("Permanently added '%s' (%s) to the list of known hosts.", host, key.Type())
	return nil
}

func getHostKeyCallback(args *sshArgs, param *sshParam) (ssh.HostKeyCallback, []string, error) {
	primaryPath := ""
	var files []string
	addKnownHostsFiles := func(key string, user bool) error {
		knownHostsFiles := getOptionConfigSplits(args, key)
		if len(knownHostsFiles) == 0 {
			debug("%s is empty", key)
			return nil
		}
		if len(knownHostsFiles) == 1 && strings.ToLower(knownHostsFiles[0]) == "none" {
			debug("%s is none", key)
			return nil
		}
		for _, path := range knownHostsFiles {
			var resolvedPath string
			if user {
				expandedPath, err := expandTokens(path, args, param, "%CdhijkLlnpru")
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
	if err := addKnownHostsFiles("UserKnownHostsFile", true); err != nil {
		return nil, nil, err
	}
	if err := addKnownHostsFiles("GlobalKnownHostsFile", false); err != nil {
		return nil, nil, err
	}

	khdb, err := knownhosts.NewDB(files...)
	if err != nil {
		return nil, nil, fmt.Errorf("new knownhosts failed: %v", err)
	}

	hostKeyCallback := func(host string, remote net.Addr, key ssh.PublicKey) error {
		err := khdb.HostKeyCallback()(host, remote, key)
		if err == nil {
			return nil
		}
		strictHostKeyChecking := strings.ToLower(getOptionConfig(args, "StrictHostKeyChecking"))
		if knownhosts.IsHostKeyChanged(err) {
			path := primaryPath
			if path == "" {
				path = "~/.ssh/known_hosts"
			}
			fmt.Fprintf(os.Stderr, "\033[0;31m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n"+
				"@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\r\n"+
				"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n"+
				"IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\r\n"+
				"Someone could be eavesdropping on you right now (man-in-the-middle attack)!\033[0m\r\n"+
				"It is also possible that a host key has just been changed.\r\n"+
				"The fingerprint for the %s key sent by the remote host is\r\n"+
				"%s\r\n"+
				"Please contact your system administrator.\r\n"+
				"Add correct host key in %s to get rid of this message.\r\n",
				key.Type(), ssh.FingerprintSHA256(key), path)
		} else if knownhosts.IsHostUnknown(err) && primaryPath != "" {
			ask := true
			switch strictHostKeyChecking {
			case "yes":
				return err
			case "accept-new", "no", "off":
				ask = false
			}
			return addHostKey(primaryPath, host, key, ask)
		}
		switch strictHostKeyChecking {
		case "no", "off":
			return nil
		default:
			return err
		}
	}

	return hostKeyCallback, khdb.HostKeyAlgorithms(param.addr), err
}

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
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/trzsz/trzsz-ssh/internal/krb5"
	"golang.org/x/crypto/ssh"
)

func getKrb5Config() string {
	if krb5Config := os.Getenv("KRB5_CONFIG"); krb5Config != "" {
		if isFileExist(krb5Config) {
			return krb5Config
		}
		warning("The krb5 config file [%s] specified by the KRB5_CONFIG environment variable does not exist", krb5Config)
		return ""
	}

	krb5ConfigPaths := []string{"/etc/krb5.conf", "/etc/krb5/krb5.conf"}
	if runtime.GOOS == "windows" {
		krb5ConfigPaths = []string{"C:\\ProgramData\\MIT\\Kerberos5\\krb5.ini"}
	}
	for _, krb5Config := range krb5ConfigPaths {
		if !isFileExist(krb5Config) {
			debug("default krb5 config file [%s] does not exist", krb5Config)
			continue
		}
		return krb5Config
	}

	return ""
}

func getKrb5CacheFile() string {
	if cachePath := os.Getenv("KRB5CCNAME"); cachePath != "" {
		if strings.HasPrefix(cachePath, "FILE:") {
			cachePath = cachePath[5:]
		} else if strings.HasPrefix(cachePath, "DIR:") {
			cachePath = filepath.Join(cachePath[4:], "tkt")
		}
		if isFileExist(cachePath) {
			return cachePath
		}
		warning("The krb5 cache file [%s] specified by the KRB5CCNAME environment variable does not exist", cachePath)
		return ""
	}

	currentUser, err := user.Current()
	if err != nil {
		warning("get current user for krb5 cache file failed: %v", err)
		return ""
	}

	var cachePath string
	if runtime.GOOS == "windows" {
		userName := currentUser.Username
		if idx := strings.LastIndexByte(userName, '\\'); idx >= 0 {
			userName = userName[idx+1:]
		}
		cachePath = filepath.Join(userHomeDir, "krb5cc_"+userName)
	} else {
		cachePath = fmt.Sprintf("/tmp/krb5cc_%s", currentUser.Uid)
	}

	if !isFileExist(cachePath) {
		debug("default krb5 cache file [%s] does not exist", cachePath)
		return ""
	}
	return cachePath
}

func getGSSAPIWithMICAuthMethod(args *sshArgs, host string) ssh.AuthMethod {
	if strings.ToLower(getOptionConfig(args, "GSSAPIAuthentication")) != "yes" {
		debug("disable auth method: gssapi-with-mic authentication")
		return nil
	}

	krb5Config := getKrb5Config()
	if krb5Config == "" {
		return nil
	}
	debug("krb5 config path: %s", krb5Config)

	krb5CacheFile := getKrb5CacheFile()
	if krb5CacheFile == "" {
		return nil
	}
	debug("krb5 cache file: %s", krb5CacheFile)

	krb5Client, err := krb5.NewKrb5InitiatorClientWithCache(krb5Config, krb5CacheFile)
	if err != nil {
		warning("new krb5 client with config [%s] cache [%s] failed: %v", krb5Config, krb5CacheFile, err)
		return nil
	}

	hostName := host
	if ips, _ := net.LookupIP(host); len(ips) > 0 {
		if names, _ := net.LookupAddr(ips[0].String()); len(names) > 0 {
			hostName = strings.TrimRight(names[0], ".")
		}
	}
	debug("krb5 host name: %s", hostName)

	return ssh.GSSAPIWithMICAuthMethod(&krb5Client, hostName)
}

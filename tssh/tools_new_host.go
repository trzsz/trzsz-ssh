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
	"path/filepath"
	"strconv"
	"time"
	"unicode"

	"github.com/trzsz/ssh_config"
)

type newHostTool struct {
	configPath     string
	hostAlias      string
	hostName       string
	hostPort       uint16
	userName       string
	password       string
	existingConfig *ssh_config.Config
}

func (n *newHostTool) promptConfigPath() {
	n.configPath = promptTextInput("ConfigPath", userConfig.configPath, getText("newhost/config"),
		&inputValidator{func(path string) error {
			if path == "" {
				return fmt.Errorf("empty ssh config path")
			}
			stat, err := os.Stat(path)
			if os.IsNotExist(err) {
				dir := filepath.Dir(path)
				if !isDirExist(dir) {
					if err := os.MkdirAll(dir, 0700); err != nil {
						return fmt.Errorf("create directory [%s] failed: %v", dir, err)
					}
				}
			} else if err != nil {
				return fmt.Errorf("stat config path failed: %v", err)
			} else if stat.IsDir() {
				return fmt.Errorf("config path is a directory")
			}
			file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0600)
			if err != nil {
				return fmt.Errorf("open config file failed: %v", err)
			}
			defer func() { _ = file.Close() }()
			n.existingConfig, err = ssh_config.Decode(file)
			if err != nil {
				return fmt.Errorf("decode existing config failed: %v", err)
			}
			return nil
		}})
}

func (n *newHostTool) promptHostAlias() {
	n.hostAlias = promptTextInput("HostAlias", "", getText("newhost/alias"),
		&inputValidator{func(alias string) error {
			if alias == "" {
				return fmt.Errorf("empty host alias")
			}
			for _, r := range alias {
				if unicode.IsSpace(r) {
					return fmt.Errorf("host alias contains spaces: %#x", r)
				}
				if !unicode.IsPrint(r) {
					return fmt.Errorf("host alias contains invisible characters: %x", r)
				}
			}
			hostName, err := n.existingConfig.Get(alias, "HostName")
			if err != nil {
				return fmt.Errorf("check existing host alias failed: %v", err)
			}
			if hostName != "" {
				return fmt.Errorf("host alias already exists, host name is %s", hostName)
			}
			return nil
		}})
}

func (n *newHostTool) promptHostName() {
	n.hostName = promptTextInput("HostName/IP", "", getText("newhost/host"),
		&inputValidator{func(name string) error {
			if name == "" {
				return fmt.Errorf("empty host name")
			}
			if _, err := net.LookupHost(name); err != nil {
				return fmt.Errorf("lookup host failed: %v", err)
			}
			return nil
		}})
}

func (n *newHostTool) promptHostPort() {
	port, _ := strconv.ParseUint(promptTextInput("HostPort", "22", getText("newhost/port"),
		&inputValidator{func(port string) error {
			if port == "" {
				return fmt.Errorf("empty host port")
			}
			if _, err := strconv.ParseUint(port, 10, 16); err != nil {
				return fmt.Errorf("invalid host port: %v", err)
			}
			conn, err := net.DialTimeout("tcp", joinHostPort(n.hostName, port), 3*time.Second)
			if err != nil {
				return fmt.Errorf("connect to server failed: %v", err)
			}
			defer func() { _ = conn.Close() }()
			return nil
		}}), 10, 16)
	n.hostPort = uint16(port)
}

func (n *newHostTool) promptUserName() {
	n.userName = promptTextInput("UserName", "", getText("newhost/user"),
		&inputValidator{func(name string) error {
			if name == "" {
				return fmt.Errorf("empty user name")
			}
			return nil
		}})
}

func (n *newHostTool) promptPassword() {
	n.password = promptPassword("Password", getText("newhost/passwd"),
		&inputValidator{func(name string) error {
			return nil
		}})
}

func (n *newHostTool) writeHost() {
	file, err := os.OpenFile(n.configPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		toolsErrorExit("open config file failed: %v", err)
	}
	defer func() { _ = file.Close() }()
	if _, err := fmt.Fprintf(file, `
Host %s
    HostName %s
    Port %d
    User %s
`, n.hostAlias, n.hostName, n.hostPort, n.userName); err != nil {
		toolsErrorExit("write config file failed: %v", err)
	}
	if n.password != "" {
		secret, err := encodeSecret([]byte(n.password))
		if err != nil {
			toolsErrorExit("encode password failed: %v", err)
		}
		if _, err := fmt.Fprintf(file, `    #!! encPassword %s
    #!! encQuestionAnswer1 %s
`, secret, secret); err != nil {
			toolsErrorExit("write config file failed: %v", err)
		}
	}
}

func (n *newHostTool) loginImmediately() bool {
	return promptBoolInput("New host added successfully. Would you like to log in now?",
		getText("newhost/login"), false)
}

func execNewHost(args *sshArgs) (int, bool) {
	n := &newHostTool{}

	chooseLanguage()

	printToolsHelp(getText("newhost/title"))

	n.promptConfigPath()

	n.promptHostAlias()

	n.promptHostName()

	n.promptHostPort()

	n.promptUserName()

	n.promptPassword()

	n.writeHost()

	if n.loginImmediately() {
		if n.configPath != userConfig.configPath {
			args.ConfigFile = n.configPath
			if err := initUserConfig(args.ConfigFile); err != nil {
				warning("init user config [%s] failed: %v", args.ConfigFile, err)
				return 1, true
			}
		}
		args.Destination = n.hostAlias
		return 0, false
	}

	return 0, true
}

/*
MIT License

Copyright (c) 2023 Lonny Wong <lonnywong@qq.com>

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
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/trzsz/ssh_config"
)

var userHomeDir string

func resolveHomeDir(path string) string {
	if strings.HasPrefix(path, "~/") || strings.HasPrefix(path, "~\\") {
		return filepath.Join(userHomeDir, path[2:])
	}
	return path
}

type sshHost struct {
	Alias         string
	Host          string
	Port          string
	User          string
	IdentityFile  string
	ProxyCommand  string
	ProxyJump     string
	RemoteCommand string
	Selected      bool
}

type tsshConfig struct {
	configPath          string
	sysConfigPath       string
	exConfigPath        string
	defaultUploadPath   string
	defaultDownloadPath string
	loadConfig          sync.Once
	loadExConfig        sync.Once
	loadHosts           sync.Once
	config              *ssh_config.Config
	sysConfig           *ssh_config.Config
	exConfig            *ssh_config.Config
	allHosts            []*sshHost
}

var userConfig = &tsshConfig{}

func parseTsshConfig() {
	path := filepath.Join(userHomeDir, ".tssh.conf")
	if !isFileExist(path) {
		debug("%s does not exist", path)
		return
	}

	file, err := os.Open(path)
	if err != nil {
		warning("open %s failed: %v", path, err)
		return
	}
	defer file.Close()
	debug("open %s success", path)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.Index(line, "#")
		if idx >= 0 {
			line = line[:idx]
		}
		idx = strings.Index(line, "=")
		if idx < 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(line[:idx]))
		value := strings.TrimSpace(line[idx+1:])
		if name == "" || value == "" {
			continue
		}
		switch {
		case name == "configpath" && userConfig.configPath == "":
			userConfig.configPath = resolveHomeDir(value)
		case name == "exconfigpath" && userConfig.exConfigPath == "":
			userConfig.exConfigPath = resolveHomeDir(value)
		case name == "defaultuploadpath" && userConfig.defaultUploadPath == "":
			userConfig.defaultUploadPath = resolveHomeDir(value)
		case name == "defaultdownloadpath" && userConfig.defaultDownloadPath == "":
			userConfig.defaultDownloadPath = resolveHomeDir(value)
		}
	}

	if userConfig.configPath != "" {
		debug("ConfigPath = %s", userConfig.configPath)
	}
	if userConfig.exConfigPath != "" {
		debug("ExConfigPath = %s", userConfig.exConfigPath)
	}
	if userConfig.defaultUploadPath != "" {
		debug("DefaultUploadPath = %s", userConfig.defaultUploadPath)
	}
	if userConfig.defaultDownloadPath != "" {
		debug("DefaultDownloadPath = %s", userConfig.defaultDownloadPath)
	}
}

func initUserConfig(configFile string) error {
	cleanupAfterLogined = append(cleanupAfterLogined, func() {
		userConfig = nil
	})

	var err error
	userHomeDir, err = os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("user home dir failed: %v", err)
	}

	if configFile != "" {
		userConfig.configPath = resolveHomeDir(configFile)
	}

	parseTsshConfig()

	if userConfig.configPath == "" {
		userConfig.configPath = filepath.Join(userHomeDir, ".ssh", "config")
		if runtime.GOOS != "windows" {
			userConfig.sysConfigPath = "/etc/ssh/ssh_config"
		}
	} else if strings.ToLower(userConfig.configPath) == "none" {
		userConfig.configPath = ""
	}

	if userConfig.exConfigPath == "" {
		userConfig.exConfigPath = filepath.Join(userHomeDir, ".ssh", "password")
	}

	return nil
}

func loadConfig(path string, system bool) *ssh_config.Config {
	file, err := os.Open(path)
	if err != nil {
		warning("open config [%s] failed: %v", path, err)
		return nil
	}
	defer file.Close()
	debug("open config [%s] success", path)

	var config *ssh_config.Config
	if system {
		config, err = ssh_config.DecodeSystemConfig(file)
	} else {
		config, err = ssh_config.Decode(file)
	}
	if err != nil {
		warning("decode config [%s] failed: %v", path, err)
		return nil
	}
	debug("decode config [%s] success", path)
	return config
}

func (c *tsshConfig) doLoadConfig() {
	c.loadConfig.Do(func() {
		ssh_config.SetDefault("IdentityFile", "")

		if c.configPath == "" {
			debug("no configuration files will be read")
			return
		}
		c.config = loadConfig(c.configPath, false)

		if c.sysConfigPath != "" {
			if !isFileExist(c.sysConfigPath) {
				debug("system config [%s] does not exist", c.sysConfigPath)
				return
			}
			c.sysConfig = loadConfig(c.sysConfigPath, true)
		}
	})
}

func getConfig(alias, key string) string {
	userConfig.doLoadConfig()

	if userConfig.config != nil {
		if value, _ := userConfig.config.Get(alias, key); value != "" {
			return value
		}
	}

	if userConfig.sysConfig != nil {
		if value, _ := userConfig.sysConfig.Get(alias, key); value != "" {
			return value
		}
	}

	return ssh_config.Default(key)
}

func getAllConfig(alias, key string) []string {
	userConfig.doLoadConfig()

	var values []string
	if userConfig.config != nil {
		if vals, _ := userConfig.config.GetAll(alias, key); len(vals) > 0 {
			values = append(values, vals...)
		}
	}
	if userConfig.sysConfig != nil {
		if vals, _ := userConfig.sysConfig.GetAll(alias, key); len(vals) > 0 {
			values = append(values, vals...)
		}
	}
	if len(values) > 0 {
		return values
	}

	if d := ssh_config.Default(key); d != "" {
		values = append(values, d)
	}
	return values
}

func getExConfig(alias, key string) string {
	userConfig.loadExConfig.Do(func() {
		if userConfig.exConfigPath == "" {
			debug("no extended configuration will be read")
			return
		}
		if !isFileExist(userConfig.exConfigPath) {
			debug("extended config [%s] does not exist", userConfig.exConfigPath)
			return
		}
		userConfig.exConfig = loadConfig(userConfig.exConfigPath, false)
	})

	if userConfig.exConfig != nil {
		value, _ := userConfig.exConfig.Get(alias, key)
		if value != "" {
			debug("get extended config [%s] for [%s] success", key, alias)
			return value
		}
	}

	debug("no extended config [%s] for [%s]", key, alias)
	return ""
}

func getAllHosts() []*sshHost {
	userConfig.loadHosts.Do(func() {
		userConfig.doLoadConfig()

		if userConfig.config != nil {
			userConfig.allHosts = append(userConfig.allHosts, recursiveGetHosts(userConfig.config.Hosts)...)
		}

		if userConfig.sysConfig != nil {
			userConfig.allHosts = append(userConfig.allHosts, recursiveGetHosts(userConfig.sysConfig.Hosts)...)
		}
	})

	return userConfig.allHosts
}

// recursiveGetHosts recursive get hosts (contains include file's hosts)
func recursiveGetHosts(cfgHosts []*ssh_config.Host) []*sshHost {
	var hosts []*sshHost
	for _, host := range cfgHosts {
		for _, node := range host.Nodes {
			if include, ok := node.(*ssh_config.Include); ok && include != nil {
				for _, config := range include.GetFiles() {
					if config != nil {
						hosts = append(hosts, recursiveGetHosts(config.Hosts)...)
					}
				}
			}
		}
		hosts = appendPromptHosts(hosts, host)
	}
	return hosts
}

func appendPromptHosts(hosts []*sshHost, cfgHosts ...*ssh_config.Host) []*sshHost {
	for _, host := range cfgHosts {
		for _, pattern := range host.Patterns {
			alias := pattern.String()
			if strings.ContainsRune(alias, '*') || strings.ContainsRune(alias, '?') {
				continue
			}
			hosts = append(hosts, &sshHost{
				Alias:         alias,
				Host:          getConfig(alias, "HostName"),
				Port:          getConfig(alias, "Port"),
				User:          getConfig(alias, "User"),
				IdentityFile:  getConfig(alias, "IdentityFile"),
				ProxyCommand:  getConfig(alias, "ProxyCommand"),
				ProxyJump:     getConfig(alias, "ProxyJump"),
				RemoteCommand: getConfig(alias, "RemoteCommand"),
			})
		}
	}
	return hosts
}

func getOptionConfig(args *sshArgs, option string) string {
	if value := args.Option.get(option); value != "" {
		return value
	}
	return getConfig(args.Destination, option)
}

func getExOptionConfig(args *sshArgs, option string) string {
	if value := args.Option.get(option); value != "" {
		return value
	}
	return getExConfig(args.Destination, option)
}

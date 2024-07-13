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
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/google/shlex"
	"github.com/mitchellh/go-homedir"
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
	GroupLabels   string
	Selected      bool
}

type tsshConfig struct {
	language            string
	configPath          string
	sysConfigPath       string
	exConfigPath        string
	defaultUploadPath   string
	defaultDownloadPath string
	promptThemeLayout   string
	promptThemeColors   map[string]string
	promptPageSize      uint8
	promptDefaultMode   string
	promptDetailItems   string
	promptCursorIcon    string
	promptSelectedIcon  string
	setTerminalTitle    string
	loadConfig          sync.Once
	loadExConfig        sync.Once
	loadHosts           sync.Once
	config              *ssh_config.Config
	sysConfig           *ssh_config.Config
	exConfig            *ssh_config.Config
	loadDefaultColors   sync.Once
	defaultThemeColors  map[string]string
	allHosts            []*sshHost
	wildcardPatterns    []*ssh_config.Pattern
}

var userConfig *tsshConfig

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
		case name == "language" && userConfig.language == "":
			userConfig.language = value
		case name == "configpath" && userConfig.configPath == "":
			userConfig.configPath = resolveHomeDir(value)
		case name == "exconfigpath" && userConfig.exConfigPath == "":
			userConfig.exConfigPath = resolveHomeDir(value)
		case name == "defaultuploadpath" && userConfig.defaultUploadPath == "":
			userConfig.defaultUploadPath = resolveHomeDir(value)
		case name == "defaultdownloadpath" && userConfig.defaultDownloadPath == "":
			userConfig.defaultDownloadPath = resolveHomeDir(value)
		case name == "promptthemelayout" && userConfig.promptThemeLayout == "":
			userConfig.promptThemeLayout = value
		case name == "promptthemecolors" && len(userConfig.promptThemeColors) == 0:
			if err := json.Unmarshal([]byte(value), &userConfig.promptThemeColors); err != nil {
				warning("PromptThemeColors %s is invalid: %v", value, err)
			}
		case name == "promptpagesize" && userConfig.promptPageSize == 0:
			pageSize, err := strconv.ParseUint(value, 10, 8)
			if err != nil {
				warning("PromptPageSize %s is invalid: %v", value, err)
			} else {
				userConfig.promptPageSize = uint8(pageSize)
			}
		case name == "promptdefaultmode" && userConfig.promptDefaultMode == "":
			userConfig.promptDefaultMode = value
		case name == "promptdetailitems" && userConfig.promptDetailItems == "":
			userConfig.promptDetailItems = value
		case name == "promptcursoricon" && userConfig.promptCursorIcon == "":
			userConfig.promptCursorIcon = value
		case name == "promptselectedicon" && userConfig.promptSelectedIcon == "":
			userConfig.promptSelectedIcon = value
		case name == "setterminaltitle" && userConfig.setTerminalTitle == "":
			userConfig.setTerminalTitle = value
		}
	}

	if userConfig.promptCursorIcon != "" {
		promptCursorIcon = userConfig.promptCursorIcon
	}
	if userConfig.promptSelectedIcon != "" {
		promptSelectedIcon = userConfig.promptSelectedIcon
	}

	if enableDebugLogging {
		showTsshConfig()
	}
}

func showTsshConfig() {
	if userConfig.language != "" {
		debug("Language = %s", userConfig.language)
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
	if userConfig.promptThemeLayout != "" {
		debug("PromptThemeLayout = %s", userConfig.promptThemeLayout)
	}
	if len(userConfig.promptThemeColors) > 0 {
		debug("PromptThemeColors = %s", userConfig.promptThemeColors)
	}
	if userConfig.promptPageSize != 0 {
		debug("PromptPageSize = %d", userConfig.promptPageSize)
	}
	if userConfig.promptDefaultMode != "" {
		debug("PromptDefaultMode = %s", userConfig.promptDefaultMode)
	}
	if userConfig.promptDetailItems != "" {
		debug("PromptDetailItems = %s", userConfig.promptDetailItems)
	}
	if userConfig.promptCursorIcon != "" {
		debug("PromptCursorIcon = %s", userConfig.promptCursorIcon)
	}
	if userConfig.promptSelectedIcon != "" {
		debug("PromptSelectedIcon = %s", userConfig.promptSelectedIcon)
	}
	if userConfig.setTerminalTitle != "" {
		debug("SetTerminalTitle = %s", userConfig.setTerminalTitle)
	}
}

func initUserConfig(configFile string) (err error) {
	userConfig = &tsshConfig{}
	userHomeDir, err = os.UserHomeDir()
	if err != nil {
		debug("user home dir failed: %v", err)
		if userHomeDir, err = homedir.Dir(); err != nil {
			debug("obtain home dir failed: %v", err)
		}
	}
	if userHomeDir == "" {
		warning("Failed to obtain the home directory. Using the current directory as the home directory.")
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
		ssh_config.SetDefault("LogLevel", "")
		ssh_config.SetDefault("IdentityFile", "")

		if c.configPath == "" {
			debug("no ssh configuration file path")
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

func (c *tsshConfig) doLoadExConfig() {
	c.loadExConfig.Do(func() {
		if c.exConfigPath == "" {
			debug("no extended configuration file path")
			return
		}
		if !isFileExist(c.exConfigPath) {
			debug("extended config [%s] does not exist", c.exConfigPath)
			return
		}
		c.exConfig = loadConfig(c.exConfigPath, false)
	})
}

func getConfig(alias, key string) string {
	userConfig.doLoadConfig()

	if userConfig.config != nil {
		value, err := userConfig.config.Get(alias, key)
		if err != nil {
			warning("get user config [%s] for [%s] failed: %v", key, alias, err)
		} else if value != "" {
			return value
		}
	}

	if userConfig.sysConfig != nil {
		value, err := userConfig.sysConfig.Get(alias, key)
		if err != nil {
			warning("get sys config [%s] for [%s] failed: %v", key, alias, err)
		} else if value != "" {
			return value
		}
	}

	return ssh_config.Default(key)
}

func getConfigSplits(alias, key string) []string {
	userConfig.doLoadConfig()

	if userConfig.config != nil {
		values, err := userConfig.config.GetSplits(alias, key)
		if err != nil {
			warning("get user config splits [%s] for [%s] failed: %v", key, alias, err)
		} else if len(values) > 0 {
			return values
		}
	}

	if userConfig.sysConfig != nil {
		values, err := userConfig.sysConfig.GetSplits(alias, key)
		if err != nil {
			warning("get sys config splits [%s] for [%s] failed: %v", key, alias, err)
		} else if len(values) > 0 {
			return values
		}
	}

	if value := ssh_config.Default(key); value != "" {
		values, err := shlex.Split(value)
		if err != nil {
			warning("split default [%s] value [%s] failed: %v", key, value, err)
		} else if len(values) > 0 {
			return values
		}
	}

	return nil
}

func getAllConfig(alias, key string) []string {
	userConfig.doLoadConfig()

	var values []string
	if userConfig.config != nil {
		vals, err := userConfig.config.GetAll(alias, key)
		if err != nil {
			warning("get all user config [%s] for [%s] failed: %v", key, alias, err)
		} else if len(vals) > 0 {
			values = append(values, vals...)
		}
	}
	if userConfig.sysConfig != nil {
		vals, err := userConfig.sysConfig.GetAll(alias, key)
		if err != nil {
			warning("get all sys config [%s] for [%s] failed: %v", key, alias, err)
		} else if len(vals) > 0 {
			values = append(values, vals...)
		}
	}
	if len(values) > 0 {
		return values
	}

	if value := ssh_config.Default(key); value != "" {
		values = append(values, value)
	}
	return values
}

func getAllConfigSplits(alias, key string) []string {
	userConfig.doLoadConfig()

	var values []string
	if userConfig.config != nil {
		vals, err := userConfig.config.GetAllSplits(alias, key)
		if err != nil {
			warning("get all user config splits [%s] for [%s] failed: %v", key, alias, err)
		} else if len(vals) > 0 {
			values = append(values, vals...)
		}
	}
	if userConfig.sysConfig != nil {
		vals, err := userConfig.sysConfig.GetAllSplits(alias, key)
		if err != nil {
			warning("get all sys config splits [%s] for [%s] failed: %v", key, alias, err)
		} else if len(vals) > 0 {
			values = append(values, vals...)
		}
	}
	if len(values) > 0 {
		return values
	}

	if value := ssh_config.Default(key); value != "" {
		vals, err := shlex.Split(value)
		if err != nil {
			warning("split default [%s] value [%s] failed: %v", key, value, err)
		} else if len(vals) > 0 {
			values = append(values, vals...)
		}
	}
	return values
}

func getExConfig(alias, key string) string {
	userConfig.doLoadExConfig()

	if userConfig.exConfig != nil {
		value, err := userConfig.exConfig.Get(alias, key)
		if err != nil {
			warning("get extended config [%s] for [%s] failed: %v", key, alias, err)
		} else if value != "" {
			debug("get extended config [%s] for [%s] success", key, alias)
			return value
		}
	}

	if value := getConfig(alias, key); value != "" {
		debug("get extended config [%s] for [%s] success", key, alias)
		return value
	}

	debug("no extended config [%s] for [%s]", key, alias)
	return ""
}

func getAllExConfig(alias, key string) []string {
	userConfig.doLoadExConfig()

	var values []string
	if userConfig.exConfig != nil {
		vals, err := userConfig.exConfig.GetAll(alias, key)
		if err != nil {
			warning("get all extended config [%s] for [%s] failed: %v", key, alias, err)
		} else if len(vals) > 0 {
			values = append(values, vals...)
		}
	}
	if vals := getAllConfig(alias, key); len(vals) > 0 {
		values = append(values, vals...)
	}

	return values
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
		afterLoginFuncs = append(afterLoginFuncs, func() {
			userConfig.allHosts = nil
			userConfig.wildcardPatterns = nil
		})
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
				if alias != "*" && !pattern.Not() {
					userConfig.wildcardPatterns = append(userConfig.wildcardPatterns, pattern)
				}
				continue
			}
			if strings.ToLower(getConfig(alias, "HideHost")) == "yes" {
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
				GroupLabels:   getGroupLabels(alias),
			})
		}
	}
	return hosts
}

func getGroupLabels(alias string) string {
	var groupLabels []string
	addGroupLabel := func(groupLabel string) {
		for _, label := range groupLabels {
			if label == groupLabel {
				return
			}
		}
		groupLabels = append(groupLabels, groupLabel)
	}
	for _, groupLabel := range getAllExConfig(alias, "GroupLabels") {
		for _, label := range strings.Fields(groupLabel) {
			addGroupLabel(label)
		}
	}
	return strings.Join(groupLabels, " ")
}

func getOptionConfig(args *sshArgs, option string) string {
	if value := args.Option.get(option); value != "" {
		return value
	}
	return getConfig(args.Destination, option)
}

func getOptionConfigSplits(args *sshArgs, option string) []string {
	if value := args.Option.get(option); value != "" {
		values, err := shlex.Split(value)
		if err != nil {
			warning("split option [%s] value [%s] failed: %v", option, value, err)
		}
		return values
	}
	return getConfigSplits(args.Destination, option)
}

func getAllOptionConfig(args *sshArgs, option string) []string {
	return append(args.Option.getAll(option), getAllConfig(args.Destination, option)...)
}

func getAllOptionConfigSplits(args *sshArgs, option string) []string {
	var all []string
	for _, value := range args.Option.getAll(option) {
		values, err := shlex.Split(value)
		if err != nil {
			warning("split option [%s] value [%s] failed: %v", option, value, err)
		} else if len(values) > 0 {
			all = append(all, values...)
		}
	}
	values := getAllConfigSplits(args.Destination, option)
	if len(values) > 0 {
		all = append(all, values...)
	}
	return all
}

func getExOptionConfig(args *sshArgs, option string) string {
	if value := args.Option.get(option); value != "" {
		return value
	}
	return getExConfig(args.Destination, option)
}

var secretEncodeKey = []byte("THE_UNSAFE_KEY_FOR_ENCODING_ONLY")

func encodeSecret(secret []byte) (string, error) {
	aesCipher, err := aes.NewCipher(secretEncodeKey)
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", aesGCM.Seal(nonce, nonce, secret, nil)), nil
}

func decodeSecret(secret string) (string, error) {
	cipherSecret, err := hex.DecodeString(secret)
	if err != nil {
		return "", err
	}
	aesCipher, err := aes.NewCipher(secretEncodeKey)
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return "", err
	}
	nonceSize := aesGCM.NonceSize()
	if len(cipherSecret) < nonceSize {
		return "", fmt.Errorf("too short")
	}
	plainSecret, err := aesGCM.Open(nil, cipherSecret[:nonceSize], cipherSecret[nonceSize:], nil)
	if err != nil {
		return "", err
	}
	return string(plainSecret), nil
}

func getSecretConfig(alias, key string) string {
	if value := getExConfig(alias, "enc"+key); value != "" {
		secret, err := decodeSecret(value)
		if err == nil && secret != "" {
			return secret
		}
		warning("decode secret [%s] failed: %v", value, err)
	}
	return getExConfig(alias, key)
}

func getPromptPageSize() int {
	if userConfig.promptPageSize != 0 {
		return int(userConfig.promptPageSize)
	}
	return 10
}

func getPromptDetailItems() []string {
	promptDetailItems := userConfig.promptDetailItems
	if promptDetailItems == "" {
		promptDetailItems = "Alias Host Port User GroupLabels IdentityFile ProxyCommand ProxyJump RemoteCommand"
	}
	return strings.Fields(promptDetailItems)
}

func getThemeColor(key string) string {
	userConfig.loadDefaultColors.Do(func() {
		colors := "{}"
		switch strings.ToLower(userConfig.promptThemeLayout) {
		case "tiny", "simple":
			colors = `{"help_tips": "faint", "shortcuts": "faint", "label_icon": "blue", "label_text": "default", "cursor_icon": "green|bold",` +
				`"active_selected": "green|bold", "active_alias": "cyan|bold", "active_host": "magenta|bold", "active_group": "blue|bold",` +
				`"inactive_selected": "green|bold", "inactive_alias": "cyan", "inactive_host": "magenta", "inactive_group": "blue",` +
				`"details_title": "default", "details_name": "faint", "details_value": "default"}`
		case "table":
			colors = `{"help_tips": "faint", "shortcuts": "faint", "table_header": "10",` +
				`"default_alias": "6", "default_host": "5", "default_group": "4",` +
				`"selected_icon": "2", "selected_alias": "14", "selected_host": "13", "selected_group": "12",` +
				`"default_border": "8", "selected_border": "10",` +
				`"details_name": "4", "details_value": "3", "details_border": "8"}`
		}
		if err := json.Unmarshal([]byte(colors), &userConfig.defaultThemeColors); err != nil {
			warning("load theme [%s] colors %s failed: %v", userConfig.promptThemeLayout, colors, err)
		}
	})
	if value, ok := userConfig.promptThemeColors[key]; ok {
		return value
	}
	if value, ok := userConfig.defaultThemeColors[key]; ok {
		return value
	}
	warning("no theme color for key [%s]", key)
	return ""
}

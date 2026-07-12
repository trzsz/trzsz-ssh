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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
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
	Args          *sshArgs
	Alias         string
	Host          string
	Port          string
	User          string
	IdentityFile  string
	ProxyCommand  string
	ProxyJump     string
	RemoteCommand string
	GroupLabels   string
	Selected      bool `json:"-"`
}

type sshConfig struct {
	path   string
	config *ssh_config.Config
}

type tsshConfig struct {
	language              string
	configPath            string
	sysConfigPath         string
	exConfigPath          string
	useOpenSSHConfig      bool
	defaultUploadPath     string
	defaultDownloadPath   string
	dragFileUploadCommand string
	progressColorPair     string
	promptThemeLayout     string
	promptThemeColors     map[string]string
	promptPageSize        uint8
	promptDefaultMode     string
	promptDetailItems     string
	promptCursorIcon      string
	promptSelectedIcon    string
	setTerminalTitle      string
	customDnsServer       string
	loadConfig            sync.Once
	loadExConfig          sync.Once
	loadHosts             sync.Once
	config                *sshConfig
	sysConfig             *sshConfig
	exConfig              *sshConfig
	loadDefaultColors     sync.Once
	defaultThemeColors    map[string]string
	allHosts              []*sshHost
	wildcardPatterns      []*ssh_config.Pattern
}

var userConfig *tsshConfig

func getTsshConfigPath() []string {
	var paths []string

	xdgConfigHome := os.Getenv("XDG_CONFIG_HOME")
	if xdgConfigHome == "" {
		xdgConfigHome = filepath.Join(userHomeDir, ".config")
	}
	xdgPath := filepath.Join(xdgConfigHome, "tssh/tssh.conf")
	if isFileExist(xdgPath) {
		paths = append(paths, xdgPath)
	}

	homePath := filepath.Join(userHomeDir, ".tssh.conf")
	if isFileExist(homePath) {
		paths = append(paths, homePath)
	}

	if enableDebugLogging && len(paths) == 0 {
		debug("%s or %s does not exist", xdgPath, homePath)
	}

	return paths
}

func createTsshConfigPath() string {
	xdgConfigHome := os.Getenv("XDG_CONFIG_HOME")
	if xdgConfigHome == "" {
		xdgConfigHome = filepath.Join(userHomeDir, ".config")
	}

	if isDirExist(xdgConfigHome) {
		cfgPath := filepath.Join(xdgConfigHome, "tssh")
		if !isDirExist(cfgPath) {
			if err := os.Mkdir(cfgPath, 0700); err != nil {
				warning("create config path [%s] failed: %v", cfgPath, err)
				return filepath.Join(userHomeDir, ".tssh.conf")
			}
		}
		return filepath.Join(cfgPath, "tssh.conf")
	}

	return filepath.Join(userHomeDir, ".tssh.conf")
}

func loadTsshConfig(path string) {
	file, err := os.Open(path)
	if err != nil {
		warning("open %s failed: %v", path, err)
		return
	}
	defer func() { _ = file.Close() }()
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
		case name == "useopensshconfig" && !userConfig.useOpenSSHConfig:
			switch strings.ToLower(value) {
			case "1", "true", "yes", "on":
				userConfig.useOpenSSHConfig = true
			}
		case name == "defaultuploadpath" && userConfig.defaultUploadPath == "":
			userConfig.defaultUploadPath = resolveHomeDir(value)
		case name == "defaultdownloadpath" && userConfig.defaultDownloadPath == "":
			userConfig.defaultDownloadPath = resolveHomeDir(value)
		case name == "dragfileuploadcommand" && userConfig.dragFileUploadCommand == "":
			userConfig.dragFileUploadCommand = value
		case name == "progresscolorpair" && userConfig.progressColorPair == "":
			userConfig.progressColorPair = value
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
		case name == "customdnsserver" && userConfig.customDnsServer == "":
			userConfig.customDnsServer = value
		}
	}
}

func parseTsshConfig() {
	for _, path := range getTsshConfigPath() {
		loadTsshConfig(path)
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
	if userConfig.useOpenSSHConfig {
		debug("UseOpenSSHConfig = true")
	}
	if userConfig.defaultUploadPath != "" {
		debug("DefaultUploadPath = %s", userConfig.defaultUploadPath)
	}
	if userConfig.defaultDownloadPath != "" {
		debug("DefaultDownloadPath = %s", userConfig.defaultDownloadPath)
	}
	if userConfig.dragFileUploadCommand != "" {
		debug("DragFileUploadCommand = %s", userConfig.dragFileUploadCommand)
	}
	if userConfig.progressColorPair != "" {
		debug("ProgressColorPair = %s", userConfig.progressColorPair)
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
	if userConfig.customDnsServer != "" {
		debug("CustomDnsServer = %s", userConfig.customDnsServer)
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

func loadConfig(path string, system bool) *sshConfig {
	file, err := os.Open(path)
	if err != nil {
		warning("open config [%s] failed: %v", path, err)
		return nil
	}
	defer func() { _ = file.Close() }()
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
	return &sshConfig{path, config}
}

func (c *tsshConfig) doLoadConfig() {
	c.loadConfig.Do(func() {
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

func getCfg(alias, key string, cfgs ...*sshConfig) string {
	for _, cfg := range cfgs {
		if cfg == nil || cfg.config == nil {
			continue
		}

		value, err := cfg.config.Get(alias, key)

		if err != nil {
			warning("get config [%s] from [%s] for [%s] failed: %v", key, cfg.path, alias, err)
			continue
		}

		if value != "" {
			return value
		}
	}

	return ""
}

func getConfig(args *sshArgs, key string) string {
	if userConfig.useOpenSSHConfig {
		if cfg := getOpenSSHEffectiveConfig(args, "", ""); cfg != nil {
			if value := cfg.get(key); value != "" {
				return value
			}
		}
	}

	userConfig.doLoadConfig()

	value := getCfg(args.Destination, key, userConfig.config, userConfig.sysConfig)
	if value != "" {
		return value
	}

	if args.canonicalDest != "" {
		return getCfg(args.canonicalDest, key, userConfig.config, userConfig.sysConfig)
	}

	return ""
}

func getCfgSplits(alias, key string, cfgs ...*sshConfig) []string {
	for _, cfg := range cfgs {
		if cfg == nil || cfg.config == nil {
			continue
		}

		values, err := cfg.config.GetSplits(alias, key)

		if err != nil {
			warning("get config splits [%s] from [%s] for [%s] failed: %v", key, cfg.path, alias, err)
			continue
		}

		if len(values) > 0 {
			return values
		}
	}

	return nil
}

func getConfigSplits(args *sshArgs, key string) []string {
	if userConfig.useOpenSSHConfig {
		if cfg := getOpenSSHEffectiveConfig(args, "", ""); cfg != nil {
			if value := cfg.get(key); value != "" {
				values, err := shlex.Split(value)
				if err != nil {
					warning("split effective config [%s] value [%s] failed: %v", key, value, err)
				} else if len(values) > 0 {
					return values
				}
			}
		}
	}

	userConfig.doLoadConfig()

	values := getCfgSplits(args.Destination, key, userConfig.config, userConfig.sysConfig)
	if len(values) > 0 {
		return values
	}

	if args.canonicalDest != "" {
		return getCfgSplits(args.canonicalDest, key, userConfig.config, userConfig.sysConfig)
	}

	return nil
}

func getAllCfg(alias, key string, cfgs ...*sshConfig) []string {
	var values []string

	for _, cfg := range cfgs {
		if cfg == nil || cfg.config == nil {
			continue
		}

		vals, err := cfg.config.GetAll(alias, key)

		if err != nil {
			warning("get all config [%s] from [%s] for [%s] failed: %v", key, cfg.path, alias, err)
			continue
		}

		if len(vals) > 0 {
			values = append(values, vals...)
		}
	}

	return values
}

func getAllConfig(args *sshArgs, key string) []string {
	if userConfig.useOpenSSHConfig {
		if cfg := getOpenSSHEffectiveConfig(args, "", ""); cfg != nil {
			if values := cfg.getAll(key); len(values) > 0 {
				return values
			}
		}
	}

	userConfig.doLoadConfig()

	values := getAllCfg(args.Destination, key, userConfig.config, userConfig.sysConfig)

	if args.canonicalDest != "" {
		vals := getAllCfg(args.canonicalDest, key, userConfig.config, userConfig.sysConfig)
		if len(vals) > 0 {
			values = append(values, vals...)
		}
	}

	return values
}

func getAllCfgSplits(alias, key string, cfgs ...*sshConfig) []string {
	var values []string

	for _, cfg := range cfgs {
		if cfg == nil || cfg.config == nil {
			continue
		}

		vals, err := cfg.config.GetAllSplits(alias, key)

		if err != nil {
			warning("get all config splits [%s] from [%s] for [%s] failed: %v", key, cfg.path, alias, err)
			continue
		}

		if len(vals) > 0 {
			values = append(values, vals...)
		}
	}

	return values
}

func getAllConfigSplits(args *sshArgs, key string) []string {
	if userConfig.useOpenSSHConfig {
		if cfg := getOpenSSHEffectiveConfig(args, "", ""); cfg != nil {
			var values []string
			for _, value := range cfg.getAll(key) {
				vals, err := shlex.Split(value)
				if err != nil {
					warning("split effective config [%s] value [%s] failed: %v", key, value, err)
				} else if len(vals) > 0 {
					values = append(values, vals...)
				}
			}
			if len(values) > 0 {
				return values
			}
		}
	}

	userConfig.doLoadConfig()

	values := getAllCfgSplits(args.Destination, key, userConfig.config, userConfig.sysConfig)

	if args.canonicalDest != "" {
		vals := getAllCfgSplits(args.canonicalDest, key, userConfig.config, userConfig.sysConfig)
		if len(vals) > 0 {
			values = append(values, vals...)
		}
	}

	return values
}

func getExConfig(args *sshArgs, key string) string {
	userConfig.doLoadExConfig()

	value := getCfg(args.Destination, key, userConfig.exConfig, userConfig.config, userConfig.sysConfig)

	if value != "" {
		debug("get extended config [%s] for [%s] success", key, args.Destination)
		return value
	}

	if args.canonicalDest != "" {
		value := getCfg(args.canonicalDest, key, userConfig.exConfig, userConfig.config, userConfig.sysConfig)
		if value != "" {
			debug("get extended config [%s] for [%s] success", key, args.canonicalDest)
			return value
		}
	}

	debug("no extended config [%s] for [%s]", key, args.Destination)
	return ""
}

func getAllExConfig(args *sshArgs, key string, extend bool) []string {
	if userConfig.useOpenSSHConfig && !extend {
		return getAllConfig(args, key)
	}

	userConfig.doLoadExConfig()

	values := getAllCfg(args.Destination, key, userConfig.exConfig, userConfig.config, userConfig.sysConfig)

	if enableDebugLogging && extend && len(values) > 0 {
		debug("get all extended config [%s] for [%s] success", key, args.Destination)
	}

	if args.canonicalDest != "" {
		vals := getAllCfg(args.canonicalDest, key, userConfig.exConfig, userConfig.config, userConfig.sysConfig)
		if len(vals) > 0 {
			if enableDebugLogging && extend {
				debug("get all extended config [%s] for [%s] success", key, args.canonicalDest)
			}
			values = append(values, vals...)
		}
	}

	if enableDebugLogging && extend && len(values) == 0 {
		debug("no extended config [%s] for [%s]", key, args.Destination)
	}

	return values
}

func getAllHosts(args *sshArgs) []*sshHost {
	userConfig.doLoadConfig()
	userConfig.doLoadExConfig()

	if enableDebugLogging && tmuxDebugPaneWriter == nil {
		enableDebugLogging = false
		defer func() { enableDebugLogging = true }()
	}

	userConfig.loadHosts.Do(func() {
		userConfig.doLoadConfig()
		seen := make(map[string]bool)
		if userConfig.config != nil {
			userConfig.allHosts = append(userConfig.allHosts, recursiveGetHosts(args, userConfig.config.config.Hosts, seen)...)
		}
		if userConfig.sysConfig != nil {
			userConfig.allHosts = append(userConfig.allHosts, recursiveGetHosts(args, userConfig.sysConfig.config.Hosts, seen)...)
		}
		addAfterLoginFunc(func() { userConfig.allHosts = nil; userConfig.wildcardPatterns = nil })
	})

	return userConfig.allHosts
}

// recursiveGetHosts recursive get hosts (contains include file's hosts)
func recursiveGetHosts(args *sshArgs, cfgHosts []*ssh_config.Host, seen map[string]bool) []*sshHost {
	var hosts []*sshHost
	for _, host := range cfgHosts {
		for _, node := range host.Nodes {
			if include, ok := node.(*ssh_config.Include); ok && include != nil {
				for _, config := range include.GetFiles() {
					if config != nil {
						hosts = append(hosts, recursiveGetHosts(args, config.Hosts, seen)...)
					}
				}
			}
		}
		hosts = appendPromptHosts(args, hosts, seen, host)
	}
	return hosts
}

func appendPromptHosts(oriArgs *sshArgs, hosts []*sshHost, seen map[string]bool, cfgHosts ...*ssh_config.Host) []*sshHost {
	for _, host := range cfgHosts {
		for _, pattern := range host.Patterns {
			alias := pattern.String()

			if seen[alias] {
				continue
			}
			seen[alias] = true

			if strings.ContainsRune(alias, '*') || strings.ContainsRune(alias, '?') {
				if alias != "*" && !pattern.Not() {
					userConfig.wildcardPatterns = append(userConfig.wildcardPatterns, pattern)
				}
				continue
			}

			args := *oriArgs
			args.Destination = alias

			if !userConfig.useOpenSSHConfig {
				canonMode := strings.ToLower(getOptionConfig(&args, "CanonicalizeHostname"))
				if canonMode == "always" || canonMode == "yes" {
					if host, err := canonicalizeHost(&args, alias); err == nil && host != alias {
						args.canonicalDest = host
					}
				}
			}

			if strings.ToLower(getExOptionConfig(&args, "HideHost")) == "yes" {
				continue
			}

			hosts = append(hosts, &sshHost{
				Args:          &args,
				Alias:         alias,
				Host:          getOptionConfig(&args, "HostName"),
				Port:          getOptionConfig(&args, "Port"),
				User:          getOptionConfig(&args, "User"),
				IdentityFile:  getOptionConfig(&args, "IdentityFile"),
				ProxyCommand:  getOptionConfig(&args, "ProxyCommand"),
				ProxyJump:     getOptionConfig(&args, "ProxyJump"),
				RemoteCommand: getOptionConfig(&args, "RemoteCommand"),
				GroupLabels:   getGroupLabels(&args),
			})
		}
	}
	return hosts
}

func getGroupLabels(args *sshArgs) string {
	var groupLabels []string
	addGroupLabel := func(groupLabel string) {
		if slices.Contains(groupLabels, groupLabel) {
			return
		}
		groupLabels = append(groupLabels, groupLabel)
	}
	for _, groupLabel := range getAllExOptionConfig(args, "GroupLabels", true) {
		for label := range strings.FieldsSeq(groupLabel) {
			addGroupLabel(label)
		}
	}
	return strings.Join(groupLabels, " ")
}

func getOptionConfig(args *sshArgs, option string) string {
	if value := args.Option.get(option); value != "" {
		return value
	}
	return getConfig(args, option)
}

func getOptionConfigSplits(args *sshArgs, option string) []string {
	if value := args.Option.get(option); value != "" {
		values, err := shlex.Split(value)
		if err != nil {
			warning("split option [%s] value [%s] failed: %v", option, value, err)
		}
		return values
	}
	return getConfigSplits(args, option)
}

func getAllOptionConfig(args *sshArgs, option string) []string {
	return append(args.Option.getAll(option), getAllConfig(args, option)...)
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
	values := getAllConfigSplits(args, option)
	if len(values) > 0 {
		all = append(all, values...)
	}
	return all
}

func getExOptionConfig(args *sshArgs, option string) string {
	if value := args.Option.get(option); value != "" {
		return value
	}
	return getExConfig(args, option)
}

func getAllExOptionConfig(args *sshArgs, option string, extend bool) []string {
	return append(args.Option.getAll(option), getAllExConfig(args, option, extend)...)
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

func execSecretCommand(param *sshParam, command string) string {
	expanded, err := expandTokens(command, param, "%hnpr")
	if err != nil {
		warning("expand secret command [%s] failed: %v", command, err)
		return ""
	}

	argv, err := splitCommandLine(expanded)
	if err != nil || len(argv) == 0 {
		warning("split secret command [%s] failed: %v", expanded, err)
		return ""
	}
	if enableDebugLogging {
		for i, arg := range argv {
			debug("secret command argv[%d] = %s", i, arg)
		}
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		if errBuf.Len() > 0 {
			warning("exec secret command [%s] failed: %v, %s", expanded, err, strings.TrimSpace(errBuf.String()))
		} else {
			warning("exec secret command [%s] failed: %v", expanded, err)
		}
		return ""
	}
	if enableDebugLogging && errBuf.Len() > 0 {
		debug("secret command stderr output: %s", errBuf.String())
	}
	return strings.TrimSpace(outBuf.String())
}

func getSecretConfig(param *sshParam, key string) string {
	if value := getExConfig(param.args, "enc"+key); value != "" {
		secret, err := decodeSecret(value)
		if err == nil && secret != "" {
			return secret
		}
		warning("decode secret [%s] failed: %v", value, err)
	}
	if command := getExConfig(param.args, key+"Command"); command != "" {
		if secret := execSecretCommand(param, command); secret != "" {
			return secret
		}
	}
	return getExConfig(param.args, key)
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
		promptDetailItems = "Alias Host Port User GroupLabels IdentityFile ProxyCommand ProxyJump RemoteCommand UdpMode TsshdPath"
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

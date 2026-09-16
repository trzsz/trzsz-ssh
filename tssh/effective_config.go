package tssh

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type effectiveSshConfig struct {
	values map[string][]string // lower-case key -> values in order
}

var openSSHEffectiveCfgCache struct {
	mu sync.Mutex
	m  map[string]*effectiveSshConfig // command key -> cfg (nil means tried but unavailable)
}

func (c *effectiveSshConfig) get(key string) string {
	if c == nil {
		return ""
	}
	vals := c.values[strings.ToLower(key)]
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

func (c *effectiveSshConfig) getAll(key string) []string {
	if c == nil {
		return nil
	}
	vals := c.values[strings.ToLower(key)]
	if len(vals) == 0 {
		return nil
	}
	return vals
}

func parseOpenSSHConfigDump(out []byte) *effectiveSshConfig {
	cfg := &effectiveSshConfig{values: make(map[string][]string)}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		idx := strings.IndexAny(line, " \t")
		if idx <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		val := strings.TrimSpace(line[idx+1:])
		if key == "" || val == "" {
			continue
		}
		cfg.values[key] = append(cfg.values[key], val)
	}
	return cfg
}

func openSSHEffectiveConfigCommandArgs(args *sshArgs, user, port string) ([]string, string) {
	cmdArgs := []string{"-G"}

	// Passing -F suppresses the system SSH config, so preserve OpenSSH's
	// default lookup unless tssh selected a different config file explicitly.
	if userConfig != nil {
		defaultPath := filepath.Join(userHomeDir, ".ssh", "config")
		customPath := args != nil && args.ConfigFile != "" || userConfig.configPath != defaultPath
		if customPath {
			configPath := userConfig.configPath
			if configPath == "" {
				configPath = os.DevNull
			}
			cmdArgs = append(cmdArgs, "-F", configPath)
		}
	}

	// Only promote User and Port from generic -o values because they affect
	// Match evaluation. Other -o values may be tssh-only directives that
	// OpenSSH would reject.
	loginName := strings.TrimSpace(user)
	if args != nil {
		if args.LoginName != "" {
			loginName = args.LoginName
		} else if loginName == "" {
			loginName = args.Option.get("User")
		}
	}
	if loginName != "" {
		cmdArgs = append(cmdArgs, "-l", loginName)
	}

	portNumber := strings.TrimSpace(port)
	if args != nil {
		if args.Port > 0 {
			portNumber = strconv.Itoa(args.Port)
		} else if portNumber == "" {
			portNumber = args.Option.get("Port")
		}
	}
	if portNumber != "" {
		cmdArgs = append(cmdArgs, "-p", portNumber)
	}

	dest := ""
	if args != nil {
		dest = args.Destination
	}
	cmdArgs = append(cmdArgs, dest)

	// The complete argv, rather than only the destination, identifies the
	// effective configuration. This prevents a prior UI lookup from being
	// reused for a later user/port/config-file variant of the same alias.
	return cmdArgs, strings.Join(cmdArgs, "\x00")
}

func getOpenSSHEffectiveConfig(args *sshArgs, user, port string) *effectiveSshConfig {
	if userConfig == nil || !userConfig.shouldUseOpenSSHConfig() {
		return nil
	}

	cmdArgs, cacheKey := openSSHEffectiveConfigCommandArgs(args, user, port)
	dest := ""
	if args != nil {
		dest = args.Destination
	}

	openSSHEffectiveCfgCache.mu.Lock()
	if openSSHEffectiveCfgCache.m == nil {
		openSSHEffectiveCfgCache.m = make(map[string]*effectiveSshConfig)
	}
	if cfg, ok := openSSHEffectiveCfgCache.m[cacheKey]; ok {
		openSSHEffectiveCfgCache.mu.Unlock()
		return cfg
	}
	// Mark as tried early to avoid repeated expensive calls.
	openSSHEffectiveCfgCache.m[cacheKey] = nil
	openSSHEffectiveCfgCache.mu.Unlock()

	sshPath, _, _, err := getOpenSSH()
	if err != nil {
		debug("OpenSSH not available, skip ssh -G config evaluation: %v", err)
		return nil
	}

	debug("effective config args: %v", cmdArgs)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, sshPath, cmdArgs...)
	out, err := cmd.Output()
	if err != nil {
		debug("ssh -G failed for [%s]: %v", dest, err)
		return nil
	}

	cfg := parseOpenSSHConfigDump(out)

	// Cache success.
	openSSHEffectiveCfgCache.mu.Lock()
	openSSHEffectiveCfgCache.m[cacheKey] = cfg
	openSSHEffectiveCfgCache.mu.Unlock()

	debug("loaded ssh -G effective config for [%s]", dest)
	return cfg
}

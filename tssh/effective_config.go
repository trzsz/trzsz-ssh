package tssh

import (
	"bufio"
	"bytes"
	"context"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type effectiveSshConfig struct {
	values map[string][]string // lower-case key -> values in order
}

var openSSHEffectiveCfgCache struct {
	mu sync.Mutex
	m  map[string]*effectiveSshConfig // dest -> cfg (nil means tried but unavailable)
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

func getOpenSSHEffectiveConfig(dest, user, port string) *effectiveSshConfig {
	if userConfig == nil || !userConfig.useOpenSSHConfig {
		return nil
	}
	host := strings.TrimSpace(dest)
	if host == "" {
		return nil
	}

	openSSHEffectiveCfgCache.mu.Lock()
	if openSSHEffectiveCfgCache.m == nil {
		openSSHEffectiveCfgCache.m = make(map[string]*effectiveSshConfig)
	}
	if cfg, ok := openSSHEffectiveCfgCache.m[host]; ok {
		openSSHEffectiveCfgCache.mu.Unlock()
		return cfg
	}
	// Mark as tried early to avoid repeated expensive calls.
	openSSHEffectiveCfgCache.m[host] = nil
	openSSHEffectiveCfgCache.mu.Unlock()

	sshPath, _, _, err := getOpenSSH()
	if err != nil {
		debug("OpenSSH not available, skip ssh -G config evaluation: %v", err)
		return nil
	}

	cmdArgs := []string{"-G"}

	// Honor tssh's chosen config file behavior.
	if userConfig != nil {
		if userConfig.configPath != "" {
			cmdArgs = append(cmdArgs, "-F", userConfig.configPath)
		}
	}

	// If user/port are explicitly specified by args/destination, pass them to
	// OpenSSH so token expansion matches tssh behavior.
	if strings.TrimSpace(user) != "" {
		cmdArgs = append(cmdArgs, "-l", user)
	}
	if strings.TrimSpace(port) != "" {
		cmdArgs = append(cmdArgs, "-p", port)
	}

	cmdArgs = append(cmdArgs, host)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, sshPath, cmdArgs...)
	out, err := cmd.Output()
	if err != nil {
		debug("ssh -G failed for [%s]: %v", host, err)
		return nil
	}

	cfg := parseOpenSSHConfigDump(out)

	// Cache success.
	openSSHEffectiveCfgCache.mu.Lock()
	openSSHEffectiveCfgCache.m[host] = cfg
	openSSHEffectiveCfgCache.mu.Unlock()

	if enableDebugLogging {
		debug("loaded ssh -G effective config for [%s]", host)
	}
	return cfg
}

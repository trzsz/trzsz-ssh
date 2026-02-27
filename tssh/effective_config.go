package tssh

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

type effectiveSshConfig struct {
	values map[string][]string // lower-case key -> values in order
}

// useOpenSSHConfigEnabled controls whether ssh -G is used as the base config.
// It is set from tssh.conf in TsshMain.
var useOpenSSHConfigEnabled bool

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
	out := make([]string, len(vals))
	copy(out, vals)
	return out
}

func devNullPath() string {
	if runtime.GOOS == "windows" {
		return "NUL"
	}
	return "/dev/null"
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

func getOpenSSHEffectiveConfig(dest string) *effectiveSshConfig {
	if !useOpenSSHConfigEnabled {
		return nil
	}
	if strings.TrimSpace(dest) == "" {
		return nil
	}

	openSSHEffectiveCfgCache.mu.Lock()
	if openSSHEffectiveCfgCache.m == nil {
		openSSHEffectiveCfgCache.m = make(map[string]*effectiveSshConfig)
	}
	if cfg, ok := openSSHEffectiveCfgCache.m[dest]; ok {
		openSSHEffectiveCfgCache.mu.Unlock()
		return cfg
	}
	// Mark as tried early to avoid repeated expensive calls.
	openSSHEffectiveCfgCache.m[dest] = nil
	openSSHEffectiveCfgCache.mu.Unlock()

	sshPath, _, _, err := getOpenSSH()
	if err != nil {
		debug("OpenSSH not available, skip ssh -G config evaluation: %v", err)
		return nil
	}

	user, host, port := parseDestination(dest)
	if host == "" {
		return nil
	}

	cmdArgs := []string{"-G"}

	// Honor tssh's chosen config file behavior.
	if userConfig != nil {
		if userConfig.configPath != "" {
			cmdArgs = append(cmdArgs, "-F", userConfig.configPath)
		}
	}

	// Derive user/port from destination for correct token expansion.
	if user != "" {
		cmdArgs = append(cmdArgs, "-l", user)
	}
	if port != "" {
		cmdArgs = append(cmdArgs, "-p", port)
	}

	cmdArgs = append(cmdArgs, host)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, sshPath, cmdArgs...)
	cmd.Env = os.Environ()
	out, err := cmd.Output()
	if err != nil {
		debug("ssh -G failed for [%s]: %v", host, err)
		return nil
	}

	cfg := parseOpenSSHConfigDump(out)
	if cfg == nil {
		return nil
	}

	// Cache success.
	openSSHEffectiveCfgCache.mu.Lock()
	openSSHEffectiveCfgCache.m[dest] = cfg
	openSSHEffectiveCfgCache.mu.Unlock()

	if enableDebugLogging {
		debug("loaded ssh -G effective config for [%s]", host)
	}
	return cfg
}

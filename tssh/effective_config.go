package tssh

import (
	"bufio"
	"bytes"
	"context"
	"os/exec"
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

func getOpenSSHEffectiveConfig(dest string, args *sshArgs, user, port string) *effectiveSshConfig {
	if userConfig == nil || !userConfig.useOpenSSHConfig {
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

	cmdArgs := []string{"-G"}

	// Forward the user-specified -F config file to ssh.
	if args != nil && args.ConfigFile != "" {
		cmdArgs = append(cmdArgs, "-F", args.ConfigFile)
	}

	// If user/port are explicitly specified by args/destination, pass them to
	// OpenSSH so token expansion matches tssh behavior.
	if args != nil && args.LoginName != "" {
		cmdArgs = append(cmdArgs, "-l", args.LoginName)
	} else if user != "" {
		cmdArgs = append(cmdArgs, "-l", user)
	}
	if args != nil && args.Port > 0 {
		cmdArgs = append(cmdArgs, "-p", strconv.Itoa(args.Port))
	} else if port != "" {
		cmdArgs = append(cmdArgs, "-p", port)
	}

	cmdArgs = append(cmdArgs, dest)

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
	openSSHEffectiveCfgCache.m[dest] = cfg
	openSSHEffectiveCfgCache.mu.Unlock()

	debug("loaded ssh -G effective config for [%s]", dest)
	return cfg
}

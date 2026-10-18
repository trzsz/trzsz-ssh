package tssh

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

type effectiveSshConfig struct {
	values map[string][]string // lower-case key -> values in order
}

var effectiveConfigCache struct {
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

func parseEffectiveConfigDump(out []byte) *effectiveSshConfig {
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

func effectiveConfigCmdArgs(args *sshArgs) []string {
	cmdArgs := []string{"-G"}

	if userConfig.sysConfigPath == "" {
		// Explicitly specify the config file to keep OpenSSH consistent with tssh
		// and prevent it from loading the default system config.
		path := userConfig.configPath
		if path == "" {
			path = os.DevNull
		}
		cmdArgs = append(cmdArgs, "-F", path)
	}

	var user string
	if args.LoginName != "" {
		user = args.LoginName
	} else if u := args.Option.get("user"); u != "" {
		user = u
	}
	if user != "" {
		cmdArgs = append(cmdArgs, "-l", user)
	}

	var port string
	if args.Port > 0 {
		port = strconv.Itoa(args.Port)
	} else if p := args.Option.get("port"); p != "" {
		port = p
	}
	if port != "" {
		cmdArgs = append(cmdArgs, "-p", port)
	}

	cmdArgs = append(cmdArgs, args.originalDest)

	return cmdArgs
}

func getEffectiveConfig(args *sshArgs) *effectiveSshConfig {
	if args.originalDest == "" {
		warning("original destination should not be empty (potential bug): %#v", args)
		return nil
	}

	cmdArgs := effectiveConfigCmdArgs(args)
	cacheKey := strings.Join(cmdArgs, "\x00")

	effectiveConfigCache.mu.Lock()
	if effectiveConfigCache.m == nil {
		effectiveConfigCache.m = make(map[string]*effectiveSshConfig)
	}
	if cfg, ok := effectiveConfigCache.m[cacheKey]; ok {
		effectiveConfigCache.mu.Unlock()
		return cfg
	}

	// Mark as tried early to avoid repeated expensive calls.
	effectiveConfigCache.m[cacheKey] = nil
	effectiveConfigCache.mu.Unlock()

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
		debug("ssh -G failed for [%s]: %v", args.originalDest, err)
		return nil
	}

	cfg := parseEffectiveConfigDump(out)

	// Cache success.
	effectiveConfigCache.mu.Lock()
	effectiveConfigCache.m[cacheKey] = cfg
	effectiveConfigCache.mu.Unlock()

	debug("loaded ssh -G effective config for [%s]", args.originalDest)
	return cfg
}

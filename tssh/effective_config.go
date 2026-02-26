package tssh

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type effectiveSshConfig struct {
	values map[string][]string // lower-case key -> values in order
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

func ensureEffectiveConfig(args *sshArgs) {
	if args == nil {
		return
	}
	if !args.OpenSSHConfig {
		return
	}
	if args.effectiveCfg != nil || args.effectiveTried {
		return
	}
	args.effectiveTried = true

	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		debug("OpenSSH not found in PATH, skip ssh -G config evaluation")
		return
	}

	dest := args.originalDest
	if dest == "" {
		dest = args.Destination
	}
	_, host, port := parseDestination(dest)
	if host == "" {
		return
	}

	cmdArgs := []string{"-G"}

	// Honor tssh's chosen config file behavior.
	cfgPath := ""
	if args.ConfigFile != "" {
		cfgPath = resolveHomeDir(args.ConfigFile)
	} else if userConfig != nil && userConfig.configPath != "" {
		cfgPath = userConfig.configPath
	}
	if strings.EqualFold(cfgPath, "none") {
		cfgPath = devNullPath()
	}
	if cfgPath != "" {
		cmdArgs = append(cmdArgs, "-F", cfgPath)
	}

	// Include user/port overrides when provided, so ssh expands tokens consistently.
	if args.LoginName != "" {
		cmdArgs = append(cmdArgs, "-l", args.LoginName)
	}
	if args.Port > 0 {
		cmdArgs = append(cmdArgs, "-p", intToString(args.Port))
	} else if port != "" {
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
		return
	}

	args.effectiveCfg = parseOpenSSHConfigDump(out)
	if enableDebugLogging {
		debug("loaded ssh -G effective config for [%s]", host)
	}
}

func intToString(v int) string {
	// local helper to avoid importing strconv across multiple files
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [32]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

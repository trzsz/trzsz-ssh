package tssh

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/trzsz/ssh_config"
)

func TestParseOpenSSHConfigDump(t *testing.T) {
	out := []byte("" +
		"hostname example.com\n" +
		"user ec2-user\n" +
		"identityfile ~/.ssh/example\n" +
		"identityfile ~/.ssh/id_ed25519\n" +
		"proxycommand sh -c \"aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters 'portNumber=22' --region ap-northeast-1\"\n" +
		"userknownhostsfile ~/.ssh/known_hosts ~/.ssh/known_hosts2\n")

	cfg := parseOpenSSHConfigDump(out)
	if cfg.get("HostName") != "example.com" {
		t.Fatalf("hostname = %q", cfg.get("HostName"))
	}
	ids := cfg.getAll("IdentityFile")
	if len(ids) != 2 {
		t.Fatalf("identityfile len = %d", len(ids))
	}
	if ids[0] != "~/.ssh/example" {
		t.Fatalf("identityfile[0] = %q", ids[0])
	}
	if cfg.get("ProxyCommand") == "" {
		t.Fatalf("proxycommand empty")
	}
}

func TestOpenSSHEffectiveConfigCommandArgs(t *testing.T) {
	oldUserConfig, oldUserHomeDir := userConfig, userHomeDir
	defer func() { userConfig, userHomeDir = oldUserConfig, oldUserHomeDir }()
	userHomeDir = "/home/test"
	userConfig = &tsshConfig{configPath: "/from/cli/config"}

	args := &sshArgs{
		ConfigFile:  "/from/cli/config",
		Destination: "alias",
		LoginName:   "cli-user",
		Port:        2200,
		Option: sshOption{options: map[string][]string{
			"user":    {"option-user"},
			"udpmode": {"yes"},
		}},
	}
	got, key := openSSHEffectiveConfigCommandArgs(args, "ignored-user", "ignored-port")
	want := []string{
		"-G", "-F", "/from/cli/config",
		"-l", "cli-user", "-p", "2200", "alias",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("command args = %#v, want %#v", got, want)
	}
	if key != strings.Join(want, "\x00") {
		t.Fatalf("cache key does not identify the complete command args: %q", key)
	}

	args = &sshArgs{
		Destination: "alias",
		Option: sshOption{options: map[string][]string{
			"user":    {"option-user"},
			"port":    {"2201"},
			"udpmode": {"yes"},
		}},
	}
	userConfig.configPath = "/from/tssh/config"
	got, _ = openSSHEffectiveConfigCommandArgs(args, "", "")
	want = []string{"-G", "-F", "/from/tssh/config", "-l", "option-user", "-p", "2201", "alias"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tssh ConfigPath and option context args = %#v, want %#v", got, want)
	}

	userConfig.configPath = filepath.Join(userHomeDir, ".ssh", "config")
	got, _ = openSSHEffectiveConfigCommandArgs(&sshArgs{Destination: "alias"}, "", "")
	want = []string{"-G", "alias"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("default config args = %#v, want %#v", got, want)
	}

	userConfig.configPath = ""
	got, _ = openSSHEffectiveConfigCommandArgs(&sshArgs{ConfigFile: "none", Destination: "alias"}, "", "")
	want = []string{"-G", "-F", os.DevNull, "alias"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("disabled config args = %#v, want %#v", got, want)
	}
}

func TestPromptHostsEvaluateMatchUserWithCustomConfig(t *testing.T) {
	if _, _, _, err := getOpenSSH(); err != nil {
		t.Skipf("OpenSSH is unavailable: %v", err)
	}

	configPath := filepath.Join(t.TempDir(), "config")
	config := `Host match-user
    HostName example.invalid

Match user alice
    Port 2201

Match user bob
    Port 2202
`
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatalf("write test config: %v", err)
	}
	parsed, err := ssh_config.DecodeBytes([]byte(config))
	if err != nil {
		t.Fatalf("parse test config: %v", err)
	}

	oldUserConfig := userConfig
	oldCache := openSSHEffectiveCfgCache.m
	defer func() {
		userConfig = oldUserConfig
		openSSHEffectiveCfgCache.mu.Lock()
		openSSHEffectiveCfgCache.m = oldCache
		openSSHEffectiveCfgCache.mu.Unlock()
	}()
	userConfig = &tsshConfig{useOpenSSHConfig: ptr(true), configPath: configPath}
	openSSHEffectiveCfgCache.mu.Lock()
	openSSHEffectiveCfgCache.m = nil
	openSSHEffectiveCfgCache.mu.Unlock()

	makeArgs := func(user string) *sshArgs {
		return &sshArgs{Option: sshOption{options: map[string][]string{
			"user":    {user},
			"udpmode": {"yes"},
		}}}
	}
	alice := appendPromptHosts(makeArgs("alice"), nil, make(map[string]bool), parsed.Hosts...)
	bob := appendPromptHosts(makeArgs("bob"), nil, make(map[string]bool), parsed.Hosts...)
	if len(alice) != 1 || len(bob) != 1 {
		t.Fatalf("prompt hosts: alice=%d, bob=%d, want 1 each", len(alice), len(bob))
	}
	if alice[0].User != "alice" || alice[0].Port != "2201" {
		t.Fatalf("alice prompt host = %#v, want user alice and port 2201", alice[0])
	}
	if bob[0].User != "bob" || bob[0].Port != "2202" {
		t.Fatalf("bob prompt host = %#v, want user bob and port 2202", bob[0])
	}
}

func TestPromptHostsIgnoreMatchExecBlock(t *testing.T) {
	config := `Host match-exec
    HostName example.invalid

Match exec "echo one two three"
    User leaked
    Port 2201

Host after-exec
    HostName after.invalid
`
	parsed, err := ssh_config.DecodeBytes([]byte(config))
	if err != nil {
		t.Fatalf("parse test config: %v", err)
	}
	oldUserConfig := userConfig
	defer func() { userConfig = oldUserConfig }()
	userConfig = &tsshConfig{}
	hosts := appendPromptHosts(&sshArgs{}, nil, make(map[string]bool), parsed.Hosts...)
	if len(hosts) != 2 {
		t.Fatalf("prompt hosts = %d, want 2", len(hosts))
	}
	if hosts[0].Alias != "match-exec" || hosts[1].Alias != "after-exec" {
		t.Fatalf("prompt host aliases = %q, %q", hosts[0].Alias, hosts[1].Alias)
	}
}

func TestPromptHostsIgnoreCombinedMatchExecBlock(t *testing.T) {
	config := `Match host MS-A2 exec "ping -n 1 -w 1000 10.112.171.219 > nul 2>&1"
  #!!EnableDragFile Yes
  HostName 10.112.171.219
  User euler

Match host MS-A2
  #!!EnableDragFile Yes
  HostName 8.152.198.198
  User euler
  Port 10001
`
	parsed, err := ssh_config.DecodeBytes([]byte(config))
	if err != nil {
		t.Fatalf("parse test config: %v", err)
	}

	oldUserConfig := userConfig
	defer func() { userConfig = oldUserConfig }()
	userConfig = &tsshConfig{}
	hosts := appendPromptHosts(&sshArgs{}, nil, make(map[string]bool), parsed.Hosts...)
	if len(hosts) != 1 {
		t.Fatalf("prompt hosts = %d, want 1", len(hosts))
	}
	if hosts[0].Alias != "MS-A2" {
		t.Fatalf("prompt host alias = %q, want MS-A2", hosts[0].Alias)
	}
}

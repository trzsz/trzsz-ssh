package tssh

import "testing"

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

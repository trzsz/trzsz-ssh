package tssh

import "testing"

func TestRemoveAliasBlockContentDeleteWholeBlock(t *testing.T) {
	content := `
Host alpha
    HostName alpha.example.com
    #!! encPassword secret

Host beta
    HostName beta.example.com
`

	updated, blockDropped, err := removeAliasBlockContent(content, "alpha")
	if err != nil {
		t.Fatalf("removeAliasBlockContent returned error: %v", err)
	}
	if !blockDropped {
		t.Fatalf("expected blockDropped to be true")
	}

	expected := "Host beta\n    HostName beta.example.com"
	if updated != expected {
		t.Fatalf("updated content mismatch:\nwant:\n%s\n\ngot:\n%s", expected, updated)
	}
}

func TestRemoveAliasBlockContentKeepSharedBlock(t *testing.T) {
	content := `Host alpha beta
    HostName shared.example.com
    #!! encPassword secret
`

	updated, blockDropped, err := removeAliasBlockContent(content, "alpha")
	if err != nil {
		t.Fatalf("removeAliasBlockContent returned error: %v", err)
	}
	if blockDropped {
		t.Fatalf("expected blockDropped to be false")
	}

	expected := `Host beta
    HostName shared.example.com
    #!! encPassword secret
`
	if updated != expected {
		t.Fatalf("updated content mismatch:\nwant:\n%s\n\ngot:\n%s", expected, updated)
	}
}

func TestRemoveAliasBlockContentNotFound(t *testing.T) {
	content := `Host alpha
    HostName alpha.example.com
`

	updated, blockDropped, err := removeAliasBlockContent(content, "missing")
	if err != nil {
		t.Fatalf("removeAliasBlockContent returned error: %v", err)
	}
	if blockDropped {
		t.Fatalf("expected blockDropped to be false")
	}
	if updated != content {
		t.Fatalf("expected content to remain unchanged")
	}
}

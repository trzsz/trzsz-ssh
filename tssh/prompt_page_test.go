package tssh

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
)

func TestGetPromptPageViewStrictLastPage(t *testing.T) {
	originalConfig := userConfig
	defer func() { userConfig = originalConfig }()

	userConfig = &tsshConfig{}
	userConfig.allHosts = make([]*sshHost, 25)
	items := make([]any, 10)
	for i := 0; i < 25; i++ {
		host := &sshHost{Index: i, Alias: "host"}
		userConfig.allHosts[i] = host
		if i >= 15 {
			items[i-15] = host
		}
	}

	view := getPromptPageView(items, 5, true)
	if len(view.hosts) != 5 {
		t.Fatalf("len(view.hosts) = %d, want 5", len(view.hosts))
	}
	if view.displayStart != 20 {
		t.Fatalf("view.displayStart = %d, want 20", view.displayStart)
	}
	if view.activeIdx != 0 {
		t.Fatalf("view.activeIdx = %d, want 0", view.activeIdx)
	}
	if view.hosts[0].Index != 20 || view.hosts[4].Index != 24 {
		t.Fatalf("unexpected host indexes in strict last page view")
	}
}

func TestGetPromptPageViewNonStrictKeepsVisibleItems(t *testing.T) {
	items := []any{
		&sshHost{Index: 5},
		&sshHost{Index: 6},
	}

	view := getPromptPageView(items, 1, false)
	if len(view.hosts) != 2 {
		t.Fatalf("len(view.hosts) = %d, want 2", len(view.hosts))
	}
	if view.displayStart != 0 {
		t.Fatalf("view.displayStart = %d, want 0", view.displayStart)
	}
	if view.activeIdx != 1 {
		t.Fatalf("view.activeIdx = %d, want 1", view.activeIdx)
	}
}

func TestStrictPagingMoveAcrossPages(t *testing.T) {
	pageSize := 10

	nextDistance := func(currentIndex int) int {
		pageStart := (currentIndex / pageSize) * pageSize
		pageEnd := pageStart + pageSize - 1
		if currentIndex < pageEnd {
			return 1
		}
		return pageStart + pageSize - currentIndex
	}

	prevDistance := func(currentIndex int) int {
		pageStart := (currentIndex / pageSize) * pageSize
		if currentIndex > pageStart {
			return 1
		}
		prevPageEnd := pageStart - 1
		return currentIndex - prevPageEnd
	}

	if got := nextDistance(9); got != 1 {
		t.Fatalf("nextDistance(9) = %d, want 1", got)
	}
	if got := nextDistance(19); got != 1 {
		t.Fatalf("nextDistance(19) = %d, want 1", got)
	}
	if got := prevDistance(10); got != 1 {
		t.Fatalf("prevDistance(10) = %d, want 1", got)
	}
	if got := prevDistance(20); got != 1 {
		t.Fatalf("prevDistance(20) = %d, want 1", got)
	}
}

func TestDeleteHostKeyOnlyInNonSearchMode(t *testing.T) {
	p := &sshPrompt{}
	if !p.deleteHost([]byte{'D'}) {
		t.Fatalf("expected D to delete host in non-search mode")
	}
	if p.deleteHost([]byte{'d'}) {
		t.Fatalf("expected d not to delete host")
	}

	p.search = true
	if p.deleteHost([]byte{'D'}) {
		t.Fatalf("expected D not to delete host in search mode")
	}
}

func TestPageDownKeepsLowercaseDAndCtrlD(t *testing.T) {
	p := &sshPrompt{}
	if !p.pageDown([]byte{'d'}) {
		t.Fatalf("expected d to keep page-down behavior")
	}
	if !p.pageDown([]byte{keyCtrlD}) {
		t.Fatalf("expected Ctrl+D to keep page-down behavior")
	}
	if p.pageDown([]byte{'D'}) {
		t.Fatalf("expected D not to page down")
	}
}

func withCyberpunkTheme(t *testing.T, width int) func() {
	t.Helper()

	originalConfig := userConfig
	originalStrictPaging := promptStrictPagingEnabled
	originalWidth := currentTerminalWidth.Load()

	userConfig = &tsshConfig{
		promptThemeLayout: "cyberpunk",
		promptThemeColors: make(map[string]string),
	}
	promptStrictPagingEnabled = false
	currentTerminalWidth.Store(int32(width))

	return func() {
		userConfig = originalConfig
		promptStrictPagingEnabled = originalStrictPaging
		currentTerminalWidth.Store(originalWidth)
	}
}

func TestCyberpunkThemeRendersProfilePanel(t *testing.T) {
	defer withCyberpunkTheme(t, 120)()

	theme := getCyberpunkTheme()
	items := []any{
		&sshHost{Alias: "prod-api", Host: "10.1.1.37", User: "root", Port: "22", GroupLabels: "prod zone-38"},
		&sshHost{Alias: "prod-worker", Host: "10.1.1.38", User: "root", Port: "22"},
	}

	output := ansi.Strip(theme.ItemsRenderer(items, 0))
	for _, want := range []string{"? SSH Alias:", "┃", "╭─[ NODE PROFILE ]", "ALIAS", "prod-api", "ROUTE", "direct"} {
		if !strings.Contains(output, want) {
			t.Fatalf("cyberpunk output missing %q:\n%s", want, output)
		}
	}
}

func TestCyberpunkThemeHidesProfilePanelOnNarrowTerminal(t *testing.T) {
	defer withCyberpunkTheme(t, 70)()

	theme := getCyberpunkTheme()
	items := []any{
		&sshHost{Alias: "prod-api", Host: "10.1.1.37", User: "root", Port: "22", GroupLabels: "prod zone-38"},
	}

	output := ansi.Strip(theme.ItemsRenderer(items, 0))
	if !strings.Contains(output, "? SSH Alias:") || !strings.Contains(output, "prod-api") {
		t.Fatalf("cyberpunk narrow output missing left list:\n%s", output)
	}
	if strings.Contains(output, "NODE PROFILE") || strings.Contains(output, "┃") {
		t.Fatalf("cyberpunk narrow output should hide profile panel:\n%s", output)
	}
}

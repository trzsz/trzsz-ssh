package tssh

import "testing"

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

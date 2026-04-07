package tssh

var promptStrictPagingEnabled = true

type promptPageView struct {
	hosts        []*sshHost
	activeIdx    int
	displayStart int
}

func getPromptPageView(items []any, activeIdx int, strict bool) promptPageView {
	hosts := make([]*sshHost, 0, len(items))
	for _, item := range items {
		if host, ok := item.(*sshHost); ok {
			hosts = append(hosts, host)
		}
	}
	if len(hosts) == 0 {
		return promptPageView{hosts: hosts, activeIdx: -1}
	}
	if !strict || activeIdx < 0 || activeIdx >= len(hosts) {
		return promptPageView{hosts: hosts, activeIdx: activeIdx}
	}

	pageSize := getPromptPageSize()
	activeHost := hosts[activeIdx]
	pageStart := (activeHost.Index / pageSize) * pageSize
	pageEnd := pageStart + pageSize
	if pageEnd > len(userConfig.allHosts) {
		pageEnd = len(userConfig.allHosts)
	}

	pageHosts := append([]*sshHost(nil), userConfig.allHosts[pageStart:pageEnd]...)
	return promptPageView{hosts: pageHosts, activeIdx: activeHost.Index - pageStart, displayStart: pageStart}
}

func isContiguousPromptHosts(hosts []*sshHost) bool {
	if len(hosts) < 2 {
		return true
	}
	for i := 1; i < len(hosts); i++ {
		if hosts[i].Index != hosts[i-1].Index+1 {
			return false
		}
	}
	return true
}

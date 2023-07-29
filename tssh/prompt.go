/*
MIT License

Copyright (c) 2023 Lonny Wong <lonnywong@qq.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package tssh

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/chzyer/readline"
	"github.com/trzsz/promptui"
	"github.com/trzsz/ssh_config"
)

const promptPageSize = 10

const (
	keyCtrlA     = '\x01'
	keyCtrlB     = '\x02'
	keyCtrlC     = '\x03'
	keyCtrlD     = '\x04'
	keyCtrlE     = '\x05'
	keyCtrlF     = '\x06'
	keyCtrlH     = '\x08'
	keyCtrlJ     = '\x0a'
	keyCtrlK     = '\x0b'
	keyCtrlL     = '\x0c'
	keyCtrlO     = '\x0f'
	keyCtrlP     = '\x10'
	keyCtrlQ     = '\x11'
	keyCtrlT     = '\x14'
	keyCtrlU     = '\x15'
	keyCtrlW     = '\x17'
	keyCtrlX     = '\x18'
	keyCtrlSpace = '\x00'
	keyEnter     = '\x0d'
	keyESC       = '\x1b'
)

type sshHost struct {
	Alias         string
	Host          string
	Port          string
	User          string
	IdentityFile  string
	ProxyCommand  string
	ProxyJump     string
	RemoteCommand string
	Selected      bool
}

type sshPrompt struct {
	selector      *promptui.Select
	pipeOut       io.WriteCloser
	hosts         []*sshHost
	termMgr       terminalManager
	openType      int
	showShortcuts bool
	search        bool
	quit          bool
}

type bellFilter struct {
	writer io.Writer
}

func (b *bellFilter) Write(p []byte) (int, error) {
	if len(p) == 1 && p[0] == readline.CharBell {
		return 1, nil
	}
	return b.writer.Write(p)
}

func (b *bellFilter) Close() error {
	return nil
}

func getAllHosts() ([]*sshHost, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("user home dir failed: %v", err)
	}
	path := filepath.Join(home, ".ssh", "config")
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config [%s] failed: %v", path, err)
	}
	cfg, err := ssh_config.Decode(f)
	if err != nil {
		return nil, fmt.Errorf("decode config [%s] failed: %v", path, err)
	}
	hosts := recursiveGetHosts(cfg.Hosts)
	if len(hosts) == 0 {
		return nil, fmt.Errorf("no config in %s", path)
	}
	return hosts, nil
}

// recursiveGetHosts recursive get hosts (contains include file's hosts)
func recursiveGetHosts(cfgHosts []*ssh_config.Host) []*sshHost {
	var hosts []*sshHost
	for _, host := range cfgHosts {
		for _, node := range host.Nodes {
			if include, ok := node.(*ssh_config.Include); ok && include != nil {
				for _, config := range include.GetFiles() {
					if config != nil {
						hosts = append(hosts, recursiveGetHosts(config.Hosts)...)
					}
				}
			}
		}
		hosts = appendPromptHosts(hosts, host)
	}
	return hosts
}

func appendPromptHosts(hosts []*sshHost, cfgHosts ...*ssh_config.Host) []*sshHost {
	for _, host := range cfgHosts {
		alias := host.Patterns[0].String()
		if strings.ContainsRune(alias, '*') || strings.ContainsRune(alias, '?') {
			continue
		}
		hosts = append(hosts, &sshHost{
			Alias:         alias,
			Host:          ssh_config.Get(alias, "HostName"),
			Port:          ssh_config.Get(alias, "Port"),
			User:          ssh_config.Get(alias, "User"),
			IdentityFile:  ssh_config.Get(alias, "IdentityFile"),
			ProxyCommand:  ssh_config.Get(alias, "ProxyCommand"),
			ProxyJump:     ssh_config.Get(alias, "ProxyJump"),
			RemoteCommand: ssh_config.Get(alias, "RemoteCommand"),
		})
	}
	return hosts
}

type sshShortcuts struct {
	actionName    string
	globalKeys    []string
	searchKeys    []string
	nonSearchKeys []string
}

var normalShortcuts = []sshShortcuts{
	{actionName: "Confirm  ", globalKeys: []string{"Enter"}, nonSearchKeys: nil},
	{actionName: "Quit/Exit", globalKeys: []string{"Ctrl+C", "Ctrl+Q"}, nonSearchKeys: []string{"q", "Q"}},
	{actionName: "Move Prev", globalKeys: []string{"Ctrl+K", "Shift+Tab", "↑"}, nonSearchKeys: []string{"k", "K"}},
	{actionName: "Move Next", globalKeys: []string{"Ctrl+J", "Tab      ", "↓"}, nonSearchKeys: []string{"j", "J"}},
	{actionName: "Page   Up", globalKeys: []string{"Ctrl+H", "Ctrl+U", "Ctrl+B", "PageUp  ", "←"}, nonSearchKeys: []string{"h", "H", "u", "U", "b", "B"}},
	{actionName: "Page Down", globalKeys: []string{"Ctrl+L", "Ctrl+D", "Ctrl+F", "PageDown", "→"}, nonSearchKeys: []string{"l", "L", "d", "D", "f", "F"}},
	{actionName: "Goto Home", globalKeys: []string{"Home"}, nonSearchKeys: []string{"g"}},
	{actionName: "Goto  End", globalKeys: []string{"End "}, nonSearchKeys: []string{"G"}},
	{actionName: "EraseKeys", globalKeys: []string{"Ctrl+E"}, nonSearchKeys: []string{"e", "E"}},
	{actionName: "TglSearch", globalKeys: []string{"/"}, searchKeys: []string{"Esc", "Enter"}},
	{actionName: "Tgl  Help", globalKeys: []string{"?"}},
}

var selectShortcuts = []sshShortcuts{
	{actionName: "TglSelect", globalKeys: []string{"Ctrl+X", "Ctrl+Space", "Alt+Space"}, nonSearchKeys: []string{"Space", "x", "X"}},
	{actionName: "SelectAll", globalKeys: []string{"Ctrl+A"}, nonSearchKeys: []string{"a", "A"}},
	{actionName: "SelectOpp", globalKeys: []string{"Ctrl+O"}, nonSearchKeys: []string{"o", "O"}},
	{actionName: "Open Wins", globalKeys: []string{"Ctrl+W"}, nonSearchKeys: []string{"w", "W"}},
	{actionName: "Open Tabs", globalKeys: []string{"Ctrl+T"}, nonSearchKeys: []string{"t", "T"}},
	{actionName: "Open Pane", globalKeys: []string{"Ctrl+P"}, nonSearchKeys: []string{"p", "P"}},
}

func (p *sshPrompt) getShortcuts() []string {
	if !p.showShortcuts {
		p.selector.HideHelp = false
		return nil
	}
	p.selector.HideHelp = true
	shortcuts := []string{"Shortcuts:"}
	addShortcuts := func(ss []sshShortcuts) {
		for _, s := range ss {
			keys := s.globalKeys
			if p.search {
				keys = append(keys, s.searchKeys...)
			} else {
				keys = append(keys, s.nonSearchKeys...)
			}
			shortcuts = append(shortcuts, fmt.Sprintf("  %s:  %s", s.actionName, strings.Join(keys, "  ")))
		}
	}
	addShortcuts(normalShortcuts)
	if p.termMgr != nil {
		addShortcuts(selectShortcuts)
	}
	return shortcuts
}

func (p *sshPrompt) getPageCount() int {
	return (len(p.hosts)-1)/promptPageSize + 1
}

func (p *sshPrompt) hasSelected() bool {
	for _, h := range p.hosts {
		if h.Selected {
			return true
		}
	}
	return false
}

func (p *sshPrompt) getSelected(idx int) []*sshHost {
	var hosts []*sshHost
	for _, h := range p.hosts {
		if h.Selected {
			hosts = append(hosts, h)
		}
	}
	if len(hosts) == 0 && idx >= 0 && idx < len(p.hosts) {
		hosts = append(hosts, p.hosts[idx])
	}
	return hosts
}

func (p *sshPrompt) userQuit(buf []byte) bool {
	if len(buf) != 1 {
		return false
	}
	switch buf[0] {
	case keyCtrlC, keyCtrlQ:
		return true
	case 'q', 'Q':
		return !p.search
	default:
		return false
	}
}

func (p *sshPrompt) movePrev(buf []byte) bool {
	if len(buf) == 3 && buf[0] == '\x1b' && buf[1] == '\x5b' {
		switch buf[2] {
		case 'A', 'Z': // ↑Arrow-Up Shift-Tab
			return true
		}
	}
	if len(buf) != 1 {
		return false
	}
	switch buf[0] {
	case keyCtrlK:
		return true
	case 'k', 'K':
		return !p.search
	default:
		return false
	}
}

func (p *sshPrompt) moveNext(buf []byte) bool {
	if len(buf) == 3 && buf[0] == '\x1b' && buf[1] == '\x5b' {
		switch buf[2] {
		case 'B': // ↓Arrow-Down
			return true
		}
	}
	if len(buf) != 1 {
		return false
	}
	switch buf[0] {
	case '\t', keyCtrlJ:
		return true
	case 'j', 'J':
		return !p.search
	default:
		return false
	}
}

func (p *sshPrompt) pageUp(buf []byte) bool {
	if len(buf) == 3 && buf[0] == '\x1b' && buf[1] == '\x5b' {
		switch buf[2] {
		case 'D': // ←Arrow-Left
			return true
		}
	}
	if len(buf) == 4 && buf[0] == '\x1b' && buf[1] == '\x5b' && buf[3] == '~' {
		switch buf[2] {
		case '5': // PageUp
			return true
		}
	}
	if len(buf) != 1 {
		return false
	}
	switch buf[0] {
	case keyCtrlH, keyCtrlU, keyCtrlB:
		return true
	case 'h', 'H', 'u', 'U', 'b', 'B':
		return !p.search
	default:
		return false
	}
}

func (p *sshPrompt) pageDown(buf []byte) bool {
	if len(buf) == 3 && buf[0] == '\x1b' && buf[1] == '\x5b' {
		switch buf[2] {
		case 'C': // →Arrow-Right
			return true
		}
	}
	if len(buf) == 4 && buf[0] == '\x1b' && buf[1] == '\x5b' && buf[3] == '~' {
		switch buf[2] {
		case '6': // PageDown
			return true
		}
	}
	if len(buf) != 1 {
		return false
	}
	switch buf[0] {
	case keyCtrlL, keyCtrlD, keyCtrlF:
		return true
	case 'l', 'L', 'd', 'D', 'f', 'F':
		return !p.search
	default:
		return false
	}
}

func (p *sshPrompt) gotoHome(buf []byte) bool {
	if len(buf) == 3 && buf[0] == '\x1b' && buf[1] == '\x5b' {
		switch buf[2] {
		case 'H': // Home
			return true
		}
	}
	if len(buf) == 4 && buf[0] == '\x1b' && buf[1] == '\x5b' && buf[3] == '~' {
		switch buf[2] {
		case '1': // Fn-Arrow-Left
			return true
		}
	}
	if len(buf) != 1 {
		return false
	}
	switch buf[0] {
	case 'g':
		return !p.search
	default:
		return false
	}
}

func (p *sshPrompt) gotoEnd(buf []byte) bool {
	if len(buf) == 3 && buf[0] == '\x1b' && buf[1] == '\x5b' {
		switch buf[2] {
		case 'F': // End
			return true
		}
	}
	if len(buf) == 4 && buf[0] == '\x1b' && buf[1] == '\x5b' && buf[3] == '~' {
		switch buf[2] {
		case '4': // Fn-Arrow-Right
			return true
		}
	}
	if len(buf) != 1 {
		return false
	}
	switch buf[0] {
	case 'G':
		return !p.search
	default:
		return false
	}
}

func (p *sshPrompt) toggleSelect(buf []byte) bool {
	if p.termMgr == nil {
		return false
	}
	if len(buf) == 2 && buf[0] == '\xc2' {
		switch buf[1] {
		case '\xa0': // Alt+Space
			return true
		}
	}
	if len(buf) != 1 {
		return false
	}
	switch buf[0] {
	case keyCtrlSpace, keyCtrlX:
		return true
	case ' ', 'x', 'X':
		return !p.search
	default:
		return false
	}
}

func (p *sshPrompt) selectAllItems(buf []byte) bool {
	if p.termMgr == nil {
		return false
	}
	if len(buf) != 1 {
		return false
	}
	switch buf[0] {
	case keyCtrlA:
		return true
	case 'a', 'A':
		return !p.search
	default:
		return false
	}
}

func (p *sshPrompt) selectOpposite(buf []byte) bool {
	if p.termMgr == nil {
		return false
	}
	if len(buf) != 1 {
		return false
	}
	switch buf[0] {
	case keyCtrlO:
		return true
	case 'o', 'O':
		return !p.search
	default:
		return false
	}
}

func (p *sshPrompt) toggleSearch(buf []byte) bool {
	if len(buf) != 1 {
		return false
	}
	switch buf[0] {
	case '/':
		return true
	case keyESC:
		return p.search
	default:
		return false
	}
}

func (p *sshPrompt) toggleShortcuts(buf []byte) bool {
	if len(buf) != 1 {
		return false
	}
	switch buf[0] {
	case '?':
		return true
	default:
		return false
	}
}

func (p *sshPrompt) addKeywords(buf []byte) bool {
	if len(buf) != 1 {
		return false
	}
	switch buf[0] {
	case keyEnter:
		return p.search && p.selector.GetVisibleSize() > 0
	default:
		return false
	}
}

func (p *sshPrompt) eraseKeywords(buf []byte) bool {
	if len(buf) != 1 {
		return false
	}
	switch buf[0] {
	case keyCtrlE:
		return true
	case 'e', 'E':
		return !p.search
	default:
		return false
	}
}

func (p *sshPrompt) userConfirm(buf []byte) bool {
	if len(buf) != 1 {
		return false
	}
	if buf[0] == keyEnter {
		p.openType = openTermDefault
		return !p.search
	}
	if p.termMgr == nil || !p.hasSelected() {
		return false
	}
	switch buf[0] {
	case keyCtrlP:
		p.openType = openTermPane
		return true
	case 'p', 'P':
		p.openType = openTermPane
		return !p.search
	case keyCtrlT:
		p.openType = openTermTab
		return true
	case 't', 'T':
		p.openType = openTermTab
		return !p.search
	case keyCtrlW:
		p.openType = openTermWindow
		return true
	case 'w', 'W':
		p.openType = openTermWindow
		return !p.search
	default:
		return false
	}
}

func (p *sshPrompt) wrapStdin() {
	defer p.selector.Stdin.Close()
	defer p.pipeOut.Close()
	buffer := make([]byte, 100)
	for {
		n, err := os.Stdin.Read(buffer)
		buf := buffer[:n]
		switch {
		case err != nil || p.userQuit(buf):
			p.quit = true
			return
		case p.movePrev(buf):
			buf = []byte{readline.CharPrev}
		case p.moveNext(buf):
			buf = []byte{readline.CharNext}
		case p.pageUp(buf):
			buf = []byte{readline.CharBackward}
		case p.pageDown(buf):
			buf = []byte{readline.CharForward}
		case p.gotoHome(buf):
			buf = bytes.Repeat([]byte{readline.CharBackward}, p.getPageCount())
		case p.gotoEnd(buf):
			buf = bytes.Repeat([]byte{readline.CharForward}, p.getPageCount())
		case p.toggleSelect(buf):
			buf = []byte{promptui.KeyRefresh}
			if idx := p.selector.GetCurrentIndex(); idx >= 0 {
				p.hosts[idx].Selected = !p.hosts[idx].Selected
			}
		case p.selectAllItems(buf):
			buf = []byte{promptui.KeyRefresh}
			for _, h := range p.selector.GetVisibleItems() {
				if host, ok := h.(*sshHost); ok {
					host.Selected = true
				}
			}
		case p.selectOpposite(buf):
			buf = []byte{promptui.KeyRefresh}
			for _, h := range p.selector.GetVisibleItems() {
				if host, ok := h.(*sshHost); ok {
					host.Selected = !host.Selected
				}
			}
		case p.toggleSearch(buf):
			p.search = !p.search
			buf = []byte{'/'}
		case p.toggleShortcuts(buf):
			p.showShortcuts = !p.showShortcuts
			buf = []byte{promptui.KeyRefresh}
		case p.addKeywords(buf):
			p.search = false
			buf = []byte{promptui.KeySoftEnter}
		case p.eraseKeywords(buf):
			p.search = false
			buf = []byte{promptui.KeyCtrlE}
		case p.userConfirm(buf):
			_, _ = p.pipeOut.Write([]byte{readline.CharEnter})
			return
		case len(buf) == 1 && buf[0] == '\x00':
			// avoid Ctrl+Space causing quit unexpectedly
			buf = []byte{promptui.KeyRefresh}
		}
		p.selector.Shortcuts = p.getShortcuts()
		_, _ = p.pipeOut.Write(buf)
	}
}

func chooseAlias() (string, bool, error) {
	hosts, err := getAllHosts()
	if err != nil {
		return "", false, err
	}

	templates := &promptui.SelectTemplates{
		Help:     `{{ "Use ← ↓ ↑ → h j k l to navigate, / toggles search, ? toggles help" | faint }}`,
		Active:   `🧨 {{ if .Selected }}{{ "✔ " | green }}{{ end }}{{ .Alias | cyan }} ({{ .Host | red }})`,
		Inactive: `   {{ if .Selected }}{{ "✔ " | green }}{{ end }}{{ .Alias | cyan }} ({{ .Host | red }})`,
		Details: `
--------- SSH Alias ----------
{{ "Alias:" | faint }}	{{ .Alias }}
{{ "Host:" | faint }}	{{ .Host }}
{{- if ne .Port "22" }}
{{ "Port:" | faint }}	{{ .Port }}
{{- end }}
{{- if .User }}
{{ "User:" | faint }}	{{ .User }}
{{- end }}
{{- if ne .IdentityFile "~/.ssh/identity" }}
{{ "IdentityFile:" | faint }}	{{ .IdentityFile }}
{{- end }}
{{- if .ProxyCommand }}
{{ "ProxyCommand:" | faint }}	{{ .ProxyCommand }}
{{- end }}
{{- if .ProxyJump }}
{{ "ProxyJump:" | faint }}	{{ .ProxyJump }}
{{- end }}
{{- if .RemoteCommand }}
{{ "RemoteCommand:" | faint }}	{{ .RemoteCommand }}
{{- end }}`,
	}

	searcher := func(input string, index int) bool {
		h := hosts[index]
		alias := strings.ReplaceAll(strings.ToLower(h.Alias), " ", "")
		host := strings.ReplaceAll(strings.ToLower(h.Host), " ", "")
		for _, token := range strings.Fields(strings.ToLower(input)) {
			if !strings.Contains(alias, token) && !strings.Contains(host, token) {
				return false
			}
		}
		return true
	}

	termMgr := getTerminalManager()

	pipeIn, pipeOut := io.Pipe()
	prompt := sshPrompt{
		selector: &promptui.Select{
			Label:        "SSH Alias",
			Items:        hosts,
			Templates:    templates,
			Size:         promptPageSize,
			Searcher:     searcher,
			Stdin:        pipeIn,
			Stdout:       &bellFilter{os.Stderr},
			HideSelected: true,
		},
		pipeOut: pipeOut,
		hosts:   hosts,
		termMgr: termMgr,
	}

	go prompt.wrapStdin()

	idx, _, err := prompt.selector.Run()
	if err != nil {
		return "", prompt.quit, fmt.Errorf("prompt choose alias failed: %v", err)
	}
	if prompt.quit {
		return "", true, nil
	}

	selectedHosts := prompt.getSelected(idx)
	for _, h := range selectedHosts {
		fmt.Fprintf(os.Stderr, "🍺 \033[0;32m%s\033[0m\r\n", h.Alias)
	}
	if len(selectedHosts) > 1 && termMgr != nil {
		termMgr.openTerminals(prompt.openType, selectedHosts)
	}
	return selectedHosts[0].Alias, false, nil
}

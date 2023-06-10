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
	"github.com/kevinburke/ssh_config"
	"github.com/manifoldco/promptui"
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
	hosts := []*sshHost{}
	for _, host := range cfg.Hosts {
		alias := host.Patterns[0].String()
		if alias == "*" {
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
	if len(hosts) == 0 {
		return nil, fmt.Errorf("no config in %s", path)
	}
	return hosts, nil
}

func getPromptStdin(pageCount int, quit *bool) io.ReadCloser {
	pipeIn, pipeOut := io.Pipe()
	go func() {
		defer pipeIn.Close()
		defer pipeOut.Close()
		search := false
		b := make([]byte, 100)
		for {
			n, _ := os.Stdin.Read(b)
			for i := 0; i < n; i++ {
				c := b[i]
				// q Ctrl-C Ctrl-Q to quit
				if !search && c == 'q' || c == '\x03' || c == '\x11' {
					*quit = true
					return
				}
				// default mappings
				switch c {
				case '\x0B': // Ctrl-K
					c = readline.CharPrev // Prev "↑"
				case '\t', '\x0A': // TAB Ctrl-J
					c = readline.CharNext // Next "↓"
				case '\x08', '\x15', '\x02': // Ctrl-H Ctrl-U Ctrl-B
					c = readline.CharBackward // PageUp "←"
				case '\x0C', '\x04', '\x06': // Ctrl-L Ctrl-D Ctrl-F
					c = readline.CharForward // PageDown "→"
				}
				// Shift-TAB
				if c == '\x1b' && n-i > 2 && b[i+1] == '[' && b[i+2] == 'Z' {
					c = readline.CharPrev // Prev "↑"
					i += 2
				}
				// normal mappings
				if !search {
					switch c {
					case 'k':
						c = readline.CharPrev // Prev "↑"
					case 'j':
						c = readline.CharNext // Next "↓"
					case 'h', 'u', 'b':
						c = readline.CharBackward // PageUp "←"
					case 'l', 'd', 'f':
						c = readline.CharForward // PageDown "→"
					}
				}
				// ? to search, esc to stop
				if !search && c == '?' || search && c == '\x1b' && i == n-1 {
					c = '/'
				}
				// toggle search
				if c == '/' {
					search = !search
				}

				buf := []byte{c}
				if !search && c == 'g' { // g to top
					buf = bytes.Repeat([]byte{readline.CharBackward}, pageCount)
				} else if !search && c == 'G' { // G to bottom
					buf = bytes.Repeat([]byte{readline.CharForward}, pageCount)
				}
				_, _ = pipeOut.Write(buf)
				if c == '\r' || c == '\n' {
					return
				}
			}
		}
	}()
	return pipeIn
}

func chooseAlias() (string, bool, error) {
	hosts, err := getAllHosts()
	if err != nil {
		return "", false, err
	}

	templates := &promptui.SelectTemplates{
		Label:    "{{ . }}?",
		Active:   "🧨 {{ .Alias | cyan }} ({{ .Host | red }})",
		Inactive: "  {{ .Alias | cyan }} ({{ .Host | red }})",
		Selected: "🍺 {{ .Alias | red | cyan }}",
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

	quit := false
	pageSize := 10
	prompt := promptui.Select{
		Label:     "SSH Alias",
		Items:     hosts,
		Templates: templates,
		Size:      pageSize,
		Searcher:  searcher,
		Stdin:     getPromptStdin((len(hosts)-1)/pageSize+1, &quit),
	}

	i, _, err := prompt.Run()
	if err != nil {
		return "", quit, fmt.Errorf("prompt choose alias failed: %#v", err)
	}
	return hosts[i].Alias, quit, nil
}

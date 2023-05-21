/*
MIT License

Copyright (c) 2023 trzsz

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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kevinburke/ssh_config"
	"github.com/manifoldco/promptui"
	"github.com/trzsz/trzsz-go/trzsz"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type sshHost struct {
	Alias string
	Host  string
	Port  string
	User  string
}

func chooseAlias() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("user home dir failed: %v", err)
	}
	path := filepath.Join(home, ".ssh", "config")
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open config [%s] failed: %v", path, err)
	}
	cfg, err := ssh_config.Decode(f)
	if err != nil {
		return "", fmt.Errorf("decode config [%s] failed: %v", path, err)
	}
	hosts := []sshHost{}
	for _, host := range cfg.Hosts {
		alias := host.Patterns[0].String()
		if alias == "*" {
			continue
		}
		host := ssh_config.Get(alias, "HostName")
		port := ssh_config.Get(alias, "Port")
		user := ssh_config.Get(alias, "User")
		hosts = append(hosts, sshHost{alias, host, port, user})
	}

	templates := &promptui.SelectTemplates{
		Label:    "{{ . }}?",
		Active:   "\U0001F336 {{ .Alias | cyan }} ({{ .Host | red }})",
		Inactive: "  {{ .Alias | cyan }} ({{ .Host | red }})",
		Selected: "\U0001F336 {{ .Alias | red | cyan }}",
		Details: `
--------- SSH Alias ----------
{{ "Alias:" | faint }}	{{ .Alias }}
{{ "Host:" | faint }}	{{ .Host }}
{{ "Port:" | faint }}	{{ .Port }}
{{ "User:" | faint }}	{{ .User }}`,
	}

	searcher := func(input string, index int) bool {
		h := hosts[index]
		alias := strings.Replace(strings.ToLower(h.Alias), " ", "", -1)
		host := strings.Replace(strings.ToLower(h.Host), " ", "", -1)
		input = strings.Replace(strings.ToLower(input), " ", "", -1)
		return strings.Contains(alias, input) || strings.Contains(host, input)
	}

	prompt := promptui.Select{
		Label:     "SSH Alias",
		Items:     hosts,
		Templates: templates,
		Size:      10,
		Searcher:  searcher,
	}

	i, _, err := prompt.Run()
	if err != nil {
		return "", err
	}
	return hosts[i].Alias, nil
}

func sshLogin(alias string) (*ssh.Session, error) {
	host := ssh_config.Get(alias, "HostName")
	port := ssh_config.Get(alias, "Port")
	user := ssh_config.Get(alias, "User")
	if host == "" || port == "" || user == "" {
		return nil, fmt.Errorf("ssh alias [%s] invalid: host=[%s] port=[%s] user=[%s]", alias, host, port, user)
	}

	// read private key
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("user home dir failed: %v", err)
	}
	var auth []ssh.AuthMethod
	addAuthMethod := func(name string) error {
		path := filepath.Join(home, ".ssh", name)
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			return nil
		}
		privateKey, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read private key [%s] failed: %v", path, err)
		}
		signer, err := ssh.ParsePrivateKey(privateKey)
		if err != nil {
			return fmt.Errorf("parse private key [%s] failed: %v", path, err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
		return nil
	}
	if err := addAuthMethod("id_rsa"); err != nil {
		return nil, err
	}
	if err := addAuthMethod("id_ed25519"); err != nil {
		return nil, err
	}
	if len(auth) == 0 {
		return nil, fmt.Errorf("no private key in %s/.ssh", home)
	}

	// ssh login
	config := &ssh.ClientConfig{
		User:            user,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO should not be used for production code
	}
	conn, err := ssh.Dial("tcp", host+":"+port, config)
	if err != nil {
		return nil, fmt.Errorf("ssh dial tcp [%v:%v] failed: %v", host, port, err)
	}
	session, err := conn.NewSession()
	if err != nil {
		return nil, fmt.Errorf("ssh new session failed: %v", err)
	}

	// request pty session
	width, height, err := getTerminalSize()
	if err != nil {
		return nil, fmt.Errorf("get terminal size failed: %v", err)
	}
	if err := session.RequestPty("xterm-256color", height, width, ssh.TerminalModes{}); err != nil {
		return nil, fmt.Errorf("request pty failed: %v", err)
	}

	// session input and output
	serverIn, err := session.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe failed: %v", err)
	}
	serverOut, err := session.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe failed: %v", err)
	}

	// create a TrzszFilter to support trzsz ( trz / tsz )
	//
	//   os.Stdin  ┌────────┐   os.Stdin   ┌─────────────┐   ServerIn   ┌────────┐
	// ───────────►│        ├─────────────►│             ├─────────────►│        │
	//             │        │              │ TrzszFilter │              │        │
	// ◄───────────│ Client │◄─────────────┤             │◄─────────────┤ Server │
	//   os.Stdout │        │   os.Stdout  └─────────────┘   ServerOut  │        │
	// ◄───────────│        │◄──────────────────────────────────────────┤        │
	//   os.Stderr └────────┘                  stderr                   └────────┘
	trzszFilter := trzsz.NewTrzszFilter(os.Stdin, os.Stdout, serverIn, serverOut, trzsz.TrzszOptions{TerminalColumns: width})
	session.Stderr = os.Stderr

	// reset terminal columns on resize
	onTerminalResize(func(width, height int) {
		trzszFilter.SetTerminalColumns(width)
		_ = session.WindowChange(height, width)
	})

	// start shell
	if err := session.Shell(); err != nil {
		return nil, fmt.Errorf("start shell failed: %v", err)
	}

	return session, nil
}

func TsshMain() int {
	// parse ssh alias
	var alias string
	if len(os.Args) == 1 {
		var err error
		alias, err = chooseAlias()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return -1
		}
	} else if len(os.Args) == 2 {
		alias = os.Args[1]
	} else {
		fmt.Fprintf(os.Stderr, "Usage: %s ssh_alias\n", os.Args[0])
		return -2
	}

	// make stdin to raw
	fd := int(os.Stdin.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "make stdin raw failed: %v\n", err)
		return -3
	}
	defer term.Restore(fd, state) // nolint:all

	// ssh login
	session, err := sshLogin(alias)
	if err != nil {
		_ = term.Restore(fd, state)
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return -4
	}

	// wait for exit
	if err := session.Wait(); err != nil {
		return -5
	}
	return 0
}

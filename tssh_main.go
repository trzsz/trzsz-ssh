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
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chzyer/readline"
	"github.com/kevinburke/ssh_config"
	"github.com/manifoldco/promptui"
	"github.com/trzsz/trzsz-go/trzsz"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
)

type sshHost struct {
	Alias string
	Host  string
	Port  string
	User  string
}

func getAllHosts() ([]sshHost, error) {
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
{{ "Port:" | faint }}	{{ .Port }}
{{ "User:" | faint }}	{{ .User }}`,
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
		return "", quit, err
	}
	return hosts[i].Alias, quit, nil
}

func createKnownHosts(path string) error {
	file, err := os.OpenFile(path, os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("create [%s] failed: %v", path, err)
	}
	defer file.Close()
	return nil
}

func addHostKey(path, host string, remote net.Addr, key ssh.PublicKey) error {
	fingerprint := ssh.FingerprintSHA256(key)
	fmt.Printf("The authenticity of host '%s' can't be established.\r\n"+
		"%s key fingerprint is %s.\r\n", host, key.Type(), fingerprint)

	defer fmt.Print("\r")
	rl, err := readline.New("Are you sure you want to continue connecting (yes/no/[fingerprint])? ")
	if err != nil {
		return err
	}
	for {
		input, err := rl.Readline()
		if err != nil {
			return err
		}
		input = strings.TrimSpace(input)
		if input == fingerprint {
			break
		}
		input = strings.ToLower(input)
		if input == "yes" {
			break
		} else if input == "no" {
			return fmt.Errorf("host key not trusted")
		} else {
			rl.SetPrompt("Please type 'yes', 'no' or the fingerprint: ")
		}
	}

	fmt.Printf("\r\033[0;33mWarning: Permanently added '%s' (%s) to the list of known hosts.\033[0m\r\n", host, key.Type())
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	knownHost := knownhosts.Normalize(host)
	_, err = file.WriteString(knownhosts.Line([]string{knownHost}, key) + "\n")
	return err
}

func getHostKeyCallback(home string) (ssh.HostKeyCallback, error) {
	path := filepath.Join(home, ".ssh", "known_hosts")
	if err := createKnownHosts(path); err != nil {
		return nil, err
	}
	khCallback, err := knownhosts.New(path)
	if err != nil {
		return nil, err
	}
	return func(host string, remote net.Addr, key ssh.PublicKey) error {
		var keyErr *knownhosts.KeyError
		err := khCallback(host, remote, key)
		if errors.As(err, &keyErr) && len(keyErr.Want) > 0 {
			fmt.Printf("\033[0;31m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n"+
				"@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\r\n"+
				"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n"+
				"IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\r\n"+
				"Someone could be eavesdropping on you right now (man-in-the-middle attack)!\033[0m\r\n"+
				"It is also possible that a host key has just been changed.\r\n"+
				"The fingerprint for the %s key sent by the remote host is\r\n"+
				"%s\r\n"+
				"Please contact your system administrator.\r\n"+
				"Add correct host key in %s to get rid of this message.\r\n",
				key.Type(), ssh.FingerprintSHA256(key), path)
			return keyErr
		} else if errors.As(err, &keyErr) && len(keyErr.Want) == 0 {
			return addHostKey(path, host, remote, key)
		}
		return err
	}, nil
}

func getAuthMethods() ([]ssh.AuthMethod, ssh.HostKeyCallback, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil, fmt.Errorf("user home dir failed: %v", err)
	}
	var authMethods []ssh.AuthMethod
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
		authMethods = append(authMethods, ssh.PublicKeys(signer))
		return nil
	}
	if err := addAuthMethod("id_rsa"); err != nil {
		return nil, nil, err
	}
	if err := addAuthMethod("id_ed25519"); err != nil {
		return nil, nil, err
	}
	if len(authMethods) == 0 {
		return nil, nil, fmt.Errorf("no private key in %s/.ssh", home)
	}

	hostkeyCallback, err := getHostKeyCallback(home)
	if err != nil {
		return nil, nil, err
	}

	return authMethods, hostkeyCallback, nil
}

func sshConnect(alias string, authMethods []ssh.AuthMethod, hostkeyCallback ssh.HostKeyCallback) (*ssh.Client, error) {
	host := ssh_config.Get(alias, "HostName")
	port := ssh_config.Get(alias, "Port")
	user := ssh_config.Get(alias, "User")
	if host == "" || port == "" || user == "" {
		return nil, fmt.Errorf("ssh alias [%s] invalid: host=[%s] port=[%s] user=[%s]", alias, host, port, user)
	}

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		Timeout:         3 * time.Second,
		HostKeyCallback: hostkeyCallback,
	}
	addr := fmt.Sprintf("%s:%s", host, port)
	proxy := ssh_config.Get(alias, "ProxyJump")

	if proxy == "" {
		client, err := ssh.Dial("tcp", addr, config)
		if err != nil {
			return nil, fmt.Errorf("ssh dial tcp [%s:%s] failed: %v", host, port, err)
		}
		return client, nil
	}

	proxyClient, err := sshConnect(proxy, authMethods, hostkeyCallback)
	if err != nil {
		return nil, err
	}
	conn, err := proxyClient.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("proxy [%s] dial tcp [%s:%s] failed: %v", proxy, host, port, err)
	}
	ncc, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		return nil, fmt.Errorf("proxy [%s] new conn [%s:%s] failed: %v", proxy, host, port, err)
	}
	return ssh.NewClient(ncc, chans, reqs), nil
}

func sshLogin(alias string) (*ssh.Session, error) {
	// ssh login
	authMethods, hostkeyCallback, err := getAuthMethods()
	if err != nil {
		return nil, err
	}
	client, err := sshConnect(alias, authMethods, hostkeyCallback)
	if err != nil {
		return nil, err
	}
	session, err := client.NewSession()
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
	trzszFilter := trzsz.NewTrzszFilter(os.Stdin, os.Stdout, serverIn, serverOut,
		trzsz.TrzszOptions{TerminalColumns: int32(width)})
	session.Stderr = os.Stderr

	// reset terminal size on resize
	onTerminalResize(func(width, height int) {
		trzszFilter.SetTerminalColumns(int32(width))
		_ = session.WindowChange(height, width)
	})

	// start shell
	if err := session.Shell(); err != nil {
		return nil, fmt.Errorf("start shell failed: %v", err)
	}

	return session, nil
}

func TsshMain() int {
	// print message after stdin reset
	var err error
	defer func() {
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
		}
	}()

	// setup terminal for Windows
	mode, err := setupTerminalMode()
	if err != nil {
		return -1
	}
	defer resetTerminalMode(mode)

	// make stdin to raw
	fd := int(os.Stdin.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		return -2
	}
	defer term.Restore(fd, state) // nolint:all

	// parse ssh alias
	var alias string
	if len(os.Args) == 1 {
		var quit bool
		alias, quit, err = chooseAlias()
		if quit {
			err = nil
			return 0
		}
		if err != nil {
			return -3
		}
	} else if len(os.Args) == 2 {
		alias = os.Args[1]
	} else {
		err = fmt.Errorf("Usage: %s ssh_alias", os.Args[0])
		return -4
	}

	// ssh login
	session, err := sshLogin(alias)
	if err != nil {
		return -5
	}

	// wait for exit
	if err := session.Wait(); err != nil {
		return -6
	}
	return 0
}

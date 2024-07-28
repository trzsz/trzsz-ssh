/*
MIT License

Copyright (c) 2023-2024 The Trzsz SSH Authors.

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
	"strings"
)

type sshOption struct {
	options map[string][]string
}

type multiStr struct {
	values []string
}

type bindArgs struct {
	binds []*bindCfg
}

type forwardArgs struct {
	cfgs []*forwardCfg
}

type sshArgs struct {
	Ver            bool        `arg:"-V,--" help:"show program's version number and exit"`
	Destination    string      `arg:"positional" help:"alias in ~/.ssh/config, or [user@]hostname[:port]"`
	Command        string      `arg:"positional" help:"command to execute instead of a login shell"`
	Argument       []string    `arg:"positional" help:"command arguments separated by spaces"`
	ForwardAgent   bool        `arg:"-A,--" help:"enable forwarding the ssh agent connection"`
	NoForwardAgent bool        `arg:"-a,--" help:"disable forwarding the ssh agent connection"`
	DisableTTY     bool        `arg:"-T,--" help:"disable pseudo-terminal allocation"`
	ForceTTY       bool        `arg:"-t,--" help:"force pseudo-terminal allocation"`
	IPv4Only       bool        `arg:"-4,--" help:"forces ssh to use IPv4 addresses only"`
	IPv6Only       bool        `arg:"-6,--" help:"forces ssh to use IPv6 addresses only"`
	Gateway        bool        `arg:"-g,--" help:"forwarding allows remote hosts to connect"`
	Background     bool        `arg:"-f,--" help:"run as a background process, implies -n"`
	NoCommand      bool        `arg:"-N,--" help:"do not execute a remote command"`
	Port           int         `arg:"-p,--" placeholder:"port" help:"port to connect to on the remote host"`
	LoginName      string      `arg:"-l,--" placeholder:"login_name" help:"the user to log in as on the remote machine"`
	Identity       multiStr    `arg:"-i,--" placeholder:"identity_file" help:"identity (private key) for public key auth"`
	CipherSpec     string      `arg:"-c,--" placeholder:"cipher_spec" help:"cipher specification for encrypting the session"`
	ConfigFile     string      `arg:"-F,--" placeholder:"configfile" help:"an alternative per-user configuration file"`
	ProxyJump      string      `arg:"-J,--" placeholder:"destination" help:"jump hosts separated by comma characters"`
	Option         sshOption   `arg:"-o,--" placeholder:"key=value" help:"options in the format used in ~/.ssh/config\ne.g., tssh -o ProxyCommand=\"ssh proxy nc %h %p\""`
	StdioForward   string      `arg:"-W,--" placeholder:"host:port" help:"forward stdin and stdout to host on port"`
	DynamicForward bindArgs    `arg:"-D,--" placeholder:"[bind_addr:]port" help:"dynamic port forwarding ( socks5 proxy )"`
	LocalForward   forwardArgs `arg:"-L,--" placeholder:"[bind_addr:]port:host:hostport" help:"local port forwarding"`
	RemoteForward  forwardArgs `arg:"-R,--" placeholder:"[bind_addr:]port:host:hostport" help:"remote port forwarding"`
	X11Untrusted   bool        `arg:"-X,--" help:"enables X11 forwarding"`
	NoX11Forward   bool        `arg:"-x,--" help:"disables X11 forwarding"`
	X11Trusted     bool        `arg:"-Y,--" help:"enables trusted X11 forwarding"`
	Reconnect      bool        `arg:"--reconnect" help:"reconnect when background(-f) process exits"`
	DragFile       bool        `arg:"--dragfile" help:"enable drag files and directories to upload"`
	TraceLog       bool        `arg:"--tracelog" help:"enable trzsz detect trace logs for debugging"`
	Relay          bool        `arg:"--relay" help:"force trzsz run as a relay on the jump server"`
	Client         bool        `arg:"--client" help:"force trzsz run as a client on the jump server"`
	Debug          bool        `arg:"--debug" help:"verbose mode for debugging, same as ssh's -vvv"`
	Zmodem         bool        `arg:"--zmodem" help:"enable zmodem lrzsz ( rz / sz ) feature"`
	Udp            bool        `arg:"--udp" help:"ssh over UDP like mosh (default mode: QUIC)"`
	TsshdPath      string      `arg:"--tsshd-path" placeholder:"path" help:"[udp] tsshd absolute path on the server"`
	NewHost        bool        `arg:"--new-host" help:"[tools] add new host to configuration"`
	EncSecret      bool        `arg:"--enc-secret" help:"[tools] encode secret for configuration"`
	InstallTrzsz   bool        `arg:"--install-trzsz" help:"[tools] install trzsz to the remote server"`
	InstallTsshd   bool        `arg:"--install-tsshd" help:"[tools] install tsshd to the remote server"`
	InstallPath    string      `arg:"--install-path" placeholder:"path" help:"[tools] install path, default: '~/.local/bin/'"`
	TrzszVersion   string      `arg:"--trzsz-version" placeholder:"x.x.x" help:"[tools] install the specified version of trzsz"`
	TrzszBinPath   string      `arg:"--trzsz-bin-path" placeholder:"path" help:"[tools] trzsz binary installation package path"`
	TsshdVersion   string      `arg:"--tsshd-version" placeholder:"x.x.x" help:"[tools] install the specified version of tsshd"`
	TsshdBinPath   string      `arg:"--tsshd-bin-path" placeholder:"path" help:"[tools] tsshd binary installation package path"`
	UploadFile     multiStr    `arg:"--upload-file" placeholder:"path" help:"[tools] upload the local file to remote server"`
	DownloadPath   string      `arg:"--download-path" placeholder:"path" help:"[tools] the local saving path for downloading"`
	originalDest   string
}

func (sshArgs) Description() string {
	return "Simple ssh client with trzsz ( trz / tsz ) support.\n"
}

func (sshArgs) Version() string {
	return fmt.Sprintf("trzsz ssh %s", kTsshVersion)
}

func (o *sshOption) UnmarshalText(b []byte) error {
	s := string(bytes.TrimSpace(b))
	pos := strings.IndexRune(s, '=')
	if pos >= 0 {
		p := strings.IndexAny(strings.TrimRight(s[:pos], " \t"), " \t")
		if p > 0 {
			pos = p
		}
	} else {
		pos = strings.IndexAny(s, " \t")
	}
	if pos < 0 {
		return fmt.Errorf("invalid option: %s", s)
	}
	key := strings.TrimSpace(s[:pos])
	value := strings.TrimSpace(s[pos+1:])
	if key == "" || value == "" {
		return fmt.Errorf("invalid option: %s", s)
	}
	if o.options == nil {
		o.options = make(map[string][]string)
	}
	o.options[strings.ToLower(key)] = append(o.options[strings.ToLower(key)], value)
	return nil
}

func (o *sshOption) get(option string) string {
	if o.options == nil {
		return ""
	}
	values := o.options[strings.ToLower(option)]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func (o *sshOption) getAll(option string) []string {
	if o.options == nil {
		return nil
	}
	return o.options[strings.ToLower(option)]
}

func (v *multiStr) UnmarshalText(b []byte) error {
	v.values = append(v.values, string(b))
	return nil
}

func (a *bindArgs) UnmarshalText(b []byte) error {
	bind, err := parseBindCfg(string(b))
	if err != nil {
		return err
	}
	a.binds = append(a.binds, bind)
	return nil
}

func (f *forwardArgs) UnmarshalText(b []byte) error {
	arg, err := parseForwardArg(string(b))
	if err != nil {
		return err
	}
	f.cfgs = append(f.cfgs, arg)
	return nil
}

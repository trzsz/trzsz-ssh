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
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	kX11ChannelType   = "x11"
	kX11RequestName   = "x11-req"
	kAgentChannelType = "auth-agent@openssh.com"
	kAgentRequestName = "auth-agent-req@openssh.com"
)

// SshClient implements a traditional SSH client that supports shells,
// subprocesses, TCP port/streamlocal forwarding and tunneled dialing.
type SshClient interface {

	// Wait blocks until the connection has shut down.
	Wait() error

	// Close closes the underlying network connection.
	Close() error

	// NewSession opens a new Session for this client.
	NewSession() (SshSession, error)

	// DialTimeout initiates a connection to the addr from the remote host.
	DialTimeout(network, addr string, timeout time.Duration) (net.Conn, error)

	// Listen requests the remote peer open a listening socket on addr.
	Listen(network, addr string) (net.Listener, error)

	// HandleChannelOpen returns a channel on which NewChannel requests
	// for the given type are sent. If the type already is being handled,
	// nil is returned. The channel is closed when the connection is closed.
	HandleChannelOpen(channelType string) <-chan ssh.NewChannel

	// SendRequest sends a global request, and returns the reply.
	SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error)
}

// SshSession represents a connection to a remote command or shell.
type SshSession interface {

	// Wait waits for the remote command to exit.
	Wait() error

	// Close closes the underlying network connection.
	Close() error

	// Shell starts a login shell on the remote host.
	Shell() error

	// Run runs cmd on the remote host.
	Run(cmd string) error

	// Start runs cmd on the remote host.
	Start(cmd string) error

	// WindowChange informs the remote host about a terminal window dimension
	// change to height rows and width columns.
	WindowChange(height, width int) error

	// Setenv sets an environment variable that will be applied to any
	// command executed by Shell or Run.
	Setenv(name, value string) error

	// StdinPipe returns a pipe that will be connected to the
	// remote command's standard input when the command starts.
	StdinPipe() (io.WriteCloser, error)

	// StdoutPipe returns a pipe that will be connected to the
	// remote command's standard output when the command starts.
	StdoutPipe() (io.Reader, error)

	// StderrPipe returns a pipe that will be connected to the
	// remote command's standard error when the command starts.
	StderrPipe() (io.Reader, error)

	// Output runs cmd on the remote host and returns its standard output.
	Output(cmd string) ([]byte, error)

	// CombinedOutput runs cmd on the remote host and returns its combined
	// standard output and standard error.
	CombinedOutput(cmd string) ([]byte, error)

	// RequestPty requests the association of a pty with the session on the remote host.
	RequestPty(term string, height, width int, termmodes ssh.TerminalModes) error

	// SendRequest sends an out-of-band channel request on the SSH channel
	// underlying the session.
	SendRequest(name string, wantReply bool, payload []byte) (bool, error)
}

// SshArgs specifies the arguments to log in to the remote server.
type SshArgs struct {

	// Destination specifies the remote server to log in to.
	// e.g., alias in ~/.ssh/config, [user@]hostname[:port].
	Destination string

	// IPv4Only forces ssh to use IPv4 addresses only
	IPv4Only bool

	// IPv6Only forces ssh to use IPv6 addresses only
	IPv6Only bool

	// Port to connect to on the remote host
	Port int

	// LoginName specifies the user to log in as on the remote machine
	LoginName string

	// Identity selects the identity (private key) for public key authentication
	Identity []string

	// CipherSpec specifies the cipher for encrypting the session
	CipherSpec string

	// ConfigFile specifies the per-user configuration file
	ConfigFile string

	// ProxyJump specifies the jump hosts separated by comma characters
	ProxyJump string

	// Option gives options in the format used in the configuration file
	Option map[string][]string

	// Debug causes ssh to print debugging messages about its progress
	Debug bool

	// Udp means using UDP protocol ( QUIC / KCP ) connection like mosh
	Udp bool

	// TsshdPath specifies the tsshd absolute path on the server
	TsshdPath string
}

// SshLogin logs in to the remote server and creates a Client.
func SshLogin(args *SshArgs) (SshClient, error) {
	options := make(map[string][]string)
	for key, values := range args.Option {
		name := strings.ToLower(key)
		if _, ok := options[name]; ok {
			return nil, fmt.Errorf("option %s is repeated", name)
		}
		options[name] = values
	}
	if err := initUserConfig(args.ConfigFile); err != nil {
		return nil, err
	}
	ss, err := sshLogin(&sshArgs{
		NoCommand:   true,
		Destination: args.Destination,
		IPv4Only:    args.IPv4Only,
		IPv6Only:    args.IPv6Only,
		Port:        args.Port,
		LoginName:   args.LoginName,
		Identity:    multiStr{args.Identity},
		CipherSpec:  args.CipherSpec,
		ConfigFile:  args.ConfigFile,
		ProxyJump:   args.ProxyJump,
		Option:      sshOption{options},
		Debug:       args.Debug,
		Udp:         args.Udp,
		TsshdPath:   args.TsshdPath,
	})
	if err != nil {
		return nil, err
	}
	return ss.client, nil
}

type sshClientSession struct {
	client    SshClient
	session   SshSession
	serverIn  io.WriteCloser
	serverOut io.Reader
	serverErr io.Reader
	param     *sshParam
	cmd       string
	tty       bool
}

func (s *sshClientSession) Close() {
	if s.serverIn != nil {
		s.serverIn.Close()
	}
	if s.session != nil {
		s.session.Close()
	}
	if s.client != nil {
		s.client.Close()
	}
}

type sshClientWrapper struct {
	client *ssh.Client
}

func (c *sshClientWrapper) Wait() error {
	return c.client.Wait()
}

func (c *sshClientWrapper) Close() error {
	return c.client.Close()
}

func (c *sshClientWrapper) NewSession() (SshSession, error) {
	return c.client.NewSession()
}

func (c *sshClientWrapper) DialTimeout(network, addr string, timeout time.Duration) (conn net.Conn, err error) {
	done := make(chan struct{}, 1)
	go func() {
		defer close(done)
		conn, err = c.client.Dial(network, addr)
		done <- struct{}{}
	}()
	select {
	case <-time.After(timeout):
		err = fmt.Errorf("dial [%s] timeout", addr)
	case <-done:
	}
	return
}

func (c *sshClientWrapper) Listen(network, addr string) (net.Listener, error) {
	return c.client.Listen(network, addr)
}

func (c *sshClientWrapper) HandleChannelOpen(channelType string) <-chan ssh.NewChannel {
	return c.client.HandleChannelOpen(channelType)
}

func (c *sshClientWrapper) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	return c.client.SendRequest(name, wantReply, payload)
}

func sshNewClient(c ssh.Conn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) SshClient {
	client := ssh.NewClient(c, chans, reqs)
	return &sshClientWrapper{client}
}

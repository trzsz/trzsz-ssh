/*
MIT License

Copyright (c) 2023-2025 The Trzsz SSH Authors.

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
	"os"
	"strings"
	"sync"
	"sync/atomic"
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

	// RequestSubsystem requests the association of a subsystem with the session on the remote host.
	// A subsystem is a predefined command that runs in the background when the ssh session is initiated
	RequestSubsystem(subsystem string) error

	// RedrawScreen clear and redraw the screen right now
	RedrawScreen()

	// GetTerminalWidth returns the width of the terminal
	GetTerminalWidth() int

	// GetExitCode returns exit code if exists
	GetExitCode() int
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
	sshConn, err := sshConnect(&sshArgs{
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
	return sshConn.client, nil
}

type sshConnection struct {
	client    SshClient
	session   SshSession
	exitChan  chan int
	serverIn  io.WriteCloser
	serverOut io.Reader
	serverErr io.Reader
	param     *sshParam
	cmd       string
	tty       bool
	closed    atomic.Bool
	exited    atomic.Bool
	waitWarn  sync.WaitGroup
}

func (c *sshConnection) Close() {
	if !c.closed.CompareAndSwap(false, true) {
		return
	}
	if c.serverIn != nil {
		_ = c.serverIn.Close()
	}
	if c.session != nil {
		_ = c.session.Close()
	}
	if c.client != nil {
		_ = c.client.Close()
	}
}

func (c *sshConnection) waitUntilExit() int {
	done := make(chan int, 1)
	go func() {
		defer close(done)
		_ = c.session.Wait()
		done <- c.session.GetExitCode()
	}()
	select {
	case code := <-c.exitChan:
		debug("force exit with code: %d", code)
		return code
	case code := <-done:
		c.waitWarn.Wait()
		debug("session wait completed with code: %d", code)
		return code
	}
}

func (c *sshConnection) forceExit(code int, msg string) {
	if !c.exited.CompareAndSwap(false, true) {
		return
	}

	if enableWarningLogging {
		c.waitWarn.Add(1)
		if isTerminal && c.tty {
			if isRunningTmuxIntegration() {
				detachTmuxIntegration()
			}
			_, _ = os.Stderr.Write([]byte("\n\r")) // make the top message still visible after exiting
		}
		warning("%s", msg)
		c.waitWarn.Done()
	}

	go func() {
		// UDP connections do not support half-close (write-only close) for now,
		// so we add extra wait time to allow all incoming data to be received.
		// See tsshd.SshUdpClient.Close for more details.
		udpClientCount := 0
		client := lastJumpUdpClient
		for client != nil {
			udpClientCount++
			client = client.proxyClient
		}
		time.Sleep(time.Duration(200+300*udpClientCount) * time.Millisecond)
		debug("closing did not trigger a normal exit")
		c.exitChan <- code
		go func() {
			time.Sleep(300 * time.Millisecond)
			debug("force exit due to normal exit timeout")
			_, _ = doWithTimeout(func() (int, error) { cleanupOnClose(); return 0, nil }, 50*time.Millisecond)
			_, _ = doWithTimeout(func() (int, error) { cleanupOnExit(); return 0, nil }, 300*time.Millisecond)
			os.Exit(kExitCodeForceExit)
		}()
	}()
	c.Close()
}

type sshSessionWrapper struct {
	ssh.Session
	height int
	width  int
}

func (s *sshSessionWrapper) RequestPty(term string, height, width int, termmodes ssh.TerminalModes) error {
	s.height, s.width = height, width
	return s.Session.RequestPty(term, height, width, termmodes)
}

func (s *sshSessionWrapper) WindowChange(height, width int) error {
	s.height, s.width = height, width
	return s.Session.WindowChange(height, width)
}

func (s *sshSessionWrapper) RedrawScreen() {
	if s.height <= 0 || s.width <= 0 {
		return
	}
	height, width := s.height, s.width
	_ = s.WindowChange(height, width+1)
	time.Sleep(10 * time.Millisecond) // fix redraw issue in `screen`
	_ = s.WindowChange(height, width)
}

func (s *sshSessionWrapper) GetTerminalWidth() int {
	return s.width
}

func (s *sshSessionWrapper) GetExitCode() int {
	return 0
}

type sshClientWrapper struct {
	client *ssh.Client
}

func (c *sshClientWrapper) Wait() error {
	return c.client.Wait()
}

func (c *sshClientWrapper) Close() error {
	_, err := doWithTimeout(func() (int, error) { return 0, c.client.Close() }, 300*time.Millisecond)
	return err
}

func (c *sshClientWrapper) NewSession() (SshSession, error) {
	session, err := c.client.NewSession()
	if err != nil {
		return nil, err
	}
	return &sshSessionWrapper{*session, 0, 0}, nil
}

func (c *sshClientWrapper) DialTimeout(network, addr string, timeout time.Duration) (conn net.Conn, err error) {
	if timeout > 0 {
		conn, err = doWithTimeout(func() (net.Conn, error) {
			return c.client.Dial(network, addr)
		}, timeout)
		return
	} else {
		return c.client.Dial(network, addr)
	}
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

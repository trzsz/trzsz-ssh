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
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	kX11ChannelType   = "x11"
	kX11RequestName   = "x11-req"
	kAgentChannelType = "auth-agent@openssh.com"
	kAgentRequestName = "auth-agent-req@openssh.com"
)

type sshClient interface {
	Wait() error
	Close() error
	NewSession() (sshSession, error)
	DialTimeout(network, addr string, timeout time.Duration) (net.Conn, error)
	Listen(network, addr string) (net.Listener, error)
	HandleChannelOpen(channelType string) <-chan ssh.NewChannel
	SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error)
}

type sshSession interface {
	Wait() error
	Close() error
	Shell() error
	Run(cmd string) error
	Start(cmd string) error
	WindowChange(height, width int) error
	Setenv(name, value string) error
	StdinPipe() (io.WriteCloser, error)
	StdoutPipe() (io.Reader, error)
	StderrPipe() (io.Reader, error)
	Output(cmd string) ([]byte, error)
	CombinedOutput(cmd string) ([]byte, error)
	RequestPty(term string, height, width int, termmodes ssh.TerminalModes) error
	SendRequest(name string, wantReply bool, payload []byte) (bool, error)
}

type sshClientSession struct {
	client    sshClient
	session   sshSession
	serverIn  io.WriteCloser
	serverOut io.Reader
	serverErr io.Reader
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

func (c *sshClientWrapper) NewSession() (sshSession, error) {
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

func sshNewClient(c ssh.Conn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) sshClient {
	client := ssh.NewClient(c, chans, reqs)
	return &sshClientWrapper{client}
}

package tssh

/*
MIT License

Copyright (c) 2023 Lonny Wong <lonnywong@qq.com>
Copyright (c) 2023 [Contributors](https://github.com/trzsz/trzsz-ssh/graphs/contributors)

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

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/trzsz/npipe"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	agentOnce   sync.Once
	agentConn   *npipe.PipeConn
	agentClient agent.ExtendedAgent
)

func getAgentAddr(args *sshArgs) string {
	if addr := getOptionConfig(args, "IdentityAgent"); addr != "" {
		if strings.ToLower(addr) == "none" {
			return ""
		}
		return addr
	}
	if addr := os.Getenv("SSH_AUTH_SOCK"); addr != "" {
		return addr
	}
	if addr := `\\.\pipe\openssh-ssh-agent`; isFileExist(addr) {
		return addr
	}
	return ""
}

func getAgentClient(args *sshArgs) agent.ExtendedAgent {
	agentOnce.Do(func() {
		addr := getAgentAddr(args)
		if addr == "" {
			debug("ssh agent named pipe is not set")
			return
		}

		var err error
		agentConn, err = npipe.DialTimeout(addr, time.Second)
		if err != nil {
			debug("dial ssh agent named pipe [%s] failed: %v", addr, err)
			return
		}

		agentClient = agent.NewClient(agentConn)
		debug("new ssh agent client [%s] success", addr)

		cleanupAfterLogined = append(cleanupAfterLogined, func() {
			agentConn.Close()
			agentConn = nil
			agentClient = nil
		})
	})
	return agentClient
}

const channelType = "auth-agent@openssh.com"

func forwardToRemote(client *ssh.Client, addr string) error {
	channels := client.HandleChannelOpen(channelType)
	if channels == nil {
		return fmt.Errorf("agent: already have handler for %s", channelType)
	}
	conn, err := npipe.DialTimeout(addr, time.Second)
	if err != nil {
		return err
	}
	conn.Close()

	go func() {
		for ch := range channels {
			channel, reqs, err := ch.Accept()
			if err != nil {
				continue
			}
			go ssh.DiscardRequests(reqs)
			go forwardNamedPipe(channel, addr)
		}
	}()
	return nil
}

func forwardNamedPipe(channel ssh.Channel, addr string) {
	conn, err := npipe.DialTimeout(addr, time.Second)
	if err != nil {
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		io.Copy(conn, channel)
		wg.Done()
	}()
	go func() {
		io.Copy(channel, conn)
		channel.CloseWrite()
		wg.Done()
	}()

	wg.Wait()
	conn.Close()
	channel.Close()
}

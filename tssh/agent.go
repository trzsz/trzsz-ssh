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
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	agentOnce   sync.Once
	agentClient agent.ExtendedAgent
)

type agentRequest struct {
}

func getAgentAddr(args *sshArgs, param *sshParam) (string, error) {
	if addr := getOptionConfig(args, "IdentityAgent"); addr != "" {
		if strings.ToLower(addr) == "none" {
			return "", nil
		}
		expandedAddr, err := expandTokens(addr, args, param, "%CdhijkLlnpru")
		if err != nil {
			return "", fmt.Errorf("expand IdentityAgent [%s] failed: %v", addr, err)
		}
		return resolveHomeDir(expandedAddr), nil
	}
	if addr := os.Getenv("SSH_AUTH_SOCK"); addr != "" {
		return resolveHomeDir(addr), nil
	}
	return getDefaultAgentAddr()
}

func getAgentClient(args *sshArgs, param *sshParam) agent.ExtendedAgent {
	agentOnce.Do(func() {
		addr, err := getAgentAddr(args, param)
		if err != nil {
			warning("get agent addr failed: %v", err)
			return
		}
		if addr == "" {
			debug("ssh agent address is not set")
			return
		}

		conn, err := dialAgent(addr)
		if err != nil {
			debug("dial ssh agent [%s] failed: %v", addr, err)
			return
		}

		agentClient = agent.NewClient(conn)
		debug("new ssh agent client [%s] success", addr)

		afterLoginFuncs = append(afterLoginFuncs, func() {
			conn.Close()
			agentClient = nil
		})
	})
	return agentClient
}

func forwardToRemote(client SshClient, addr string) error {
	channels := client.HandleChannelOpen(kAgentChannelType)
	if channels == nil {
		return fmt.Errorf("agent: already have handler for %s", kAgentChannelType)
	}
	conn, err := dialAgent(addr)
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
			go forwardAgentRequest(channel, addr)
		}
	}()
	return nil
}

func forwardAgentRequest(channel ssh.Channel, addr string) {
	conn, err := dialAgent(addr)
	if err != nil {
		debug("ssh agent dial [%s] failed: %v", addr, err)
		return
	}

	forwardChannel(channel, conn)
}

func requestAgentForwarding(session SshSession) error {
	ok, err := session.SendRequest(kAgentRequestName, true, nil)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("forwarding request denied")
	}
	return nil
}

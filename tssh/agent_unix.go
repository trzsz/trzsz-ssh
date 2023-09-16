//go:build !windows

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

package tssh

import (
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh/agent"
)

var (
	agentOnce   sync.Once
	agentConn   net.Conn
	agentClient agent.ExtendedAgent
)

func getAgentClient() agent.ExtendedAgent {
	agentOnce.Do(func() {
		sock := os.Getenv("SSH_AUTH_SOCK")
		if sock == "" {
			debug("no ssh agent environment variable SSH_AUTH_SOCK")
			return
		}

		var err error
		agentConn, err = net.DialTimeout("unix", sock, time.Second)
		if err != nil {
			debug("dial ssh agent unix socket [%s] failed: %v", sock, err)
			return
		}

		agentClient = agent.NewClient(agentConn)
		debug("new ssh agent client [%s] success", sock)
	})

	return agentClient
}

func closeAgentClient() {
	if agentConn != nil {
		agentConn.Close()
		agentConn = nil
	}
	agentClient = nil
}

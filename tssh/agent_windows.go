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
	"os"
	"sync"
	"time"

	"github.com/trzsz/npipe"
	"golang.org/x/crypto/ssh/agent"
)

var (
	agentOnce   sync.Once
	agentConn   *npipe.PipeConn
	agentClient agent.ExtendedAgent
)

func getAgentClient() agent.ExtendedAgent {
	agentOnce.Do(func() {
		name := `\\.\pipe\openssh-ssh-agent`
		if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
			name = sock
		}

		if !isFileExist(name) {
			debug("ssh agent named pipe [%s] does not exist", name)
			return
		}

		var err error
		agentConn, err = npipe.DialTimeout(name, time.Second)
		if err != nil {
			debug("dial ssh agent named pipe [%s] failed: %v", name, err)
			return
		}

		agentClient = agent.NewClient(agentConn)
		debug("new ssh agent client [%s] success", name)
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

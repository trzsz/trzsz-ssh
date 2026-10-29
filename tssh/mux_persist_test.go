//go:build !windows

/*
MIT License

Copyright (c) 2023-2026 The Trzsz SSH Authors.

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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGetControlPersist(t *testing.T) {
	oriUserConfig := userConfig
	userConfig = &tsshConfig{}
	defer func() { userConfig = oriUserConfig }()

	tests := []struct {
		value   string
		persist bool
		timeout time.Duration
	}{
		{"", false, 0},
		{"no", false, 0},
		{"yes", true, 0},
		{"0", true, 0},
		{"600", true, 10 * time.Minute},
		{"1h30m", true, 90 * time.Minute},
		{"invalid", false, 0},
	}
	for _, tt := range tests {
		args := &sshArgs{Destination: "persist-host"}
		if tt.value != "" {
			args.Option = sshOption{options: map[string][]string{"controlpersist": {tt.value}}}
		}
		persist, timeout := getControlPersist(args)
		assert.Equal(t, tt.persist, persist, tt.value)
		assert.Equal(t, tt.timeout, timeout, tt.value)
	}
}

// blockingWaitClient is a fake client whose connection stays up until done is closed.
type blockingWaitClient struct {
	*fakeSshClient
	done chan struct{}
}

func (c *blockingWaitClient) Wait() error {
	<-c.done
	return nil
}

func runPersist(m *muxMaster, client SshClient, timeout time.Duration) <-chan struct{} {
	exited := make(chan struct{})
	go func() {
		m.persist(&sshConnection{client: client}, timeout)
		close(exited)
	}()
	return exited
}

func waitClosed(t *testing.T, ch <-chan struct{}, what string, timeout time.Duration) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(timeout):
		t.Fatalf("timeout waiting for %s", what)
	}
}

func TestMuxMasterPersistIdleTimeout(t *testing.T) {
	client := &blockingWaitClient{newFakeSshClient(), make(chan struct{})}
	defer close(client.done)
	m, _ := newTestMuxMaster(t, client, nil)

	// a connected client keeps the master alive beyond the timeout
	pc := &muxProxyConn{}
	m.connMu.Lock()
	m.conns[pc] = struct{}{}
	m.connMu.Unlock()

	exited := runPersist(m, client, 200*time.Millisecond)
	select {
	case <-exited:
		t.Fatal("master exited while a client was connected")
	case <-time.After(500 * time.Millisecond):
	}

	// the timeout starts when the last client leaves
	m.removeConn(pc)
	waitClosed(t, exited, "idle exit", 2*time.Second)

	// a master nobody ever connected to exits after the timeout as well
	m2, _ := newTestMuxMaster(t, client, nil)
	waitClosed(t, runPersist(m2, client, 100*time.Millisecond), "idle exit without clients", 2*time.Second)
}

func TestMuxMasterPersistStopAndLost(t *testing.T) {
	client := &blockingWaitClient{newFakeSshClient(), make(chan struct{})}
	defer close(client.done)
	m, _ := newTestMuxMaster(t, client, nil)

	// no timeout: only `-O stop` with no client left ends it
	exited := runPersist(m, client, 0)
	select {
	case <-exited:
		t.Fatal("master without timeout exited")
	case <-time.After(300 * time.Millisecond):
	}
	m.stopListening()
	waitClosed(t, exited, "exit after stop", 2*time.Second)

	// the connection going away ends it at once
	client2 := &blockingWaitClient{newFakeSshClient(), make(chan struct{})}
	m2, _ := newTestMuxMaster(t, client2, nil)
	exited = runPersist(m2, client2, 0)
	close(client2.done)
	waitClosed(t, exited, "exit on connection lost", time.Second)
}

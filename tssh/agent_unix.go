//go:build !windows

package tssh

import (
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh/agent"
)

func getAgentSigners() []*sshSigner {
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return nil
	}

	conn, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		debug("open ssh agent [%s] failed: %v", socket, err)
		return nil
	}
	cleanupAfterLogined = append(cleanupAfterLogined, func() {
		conn.Close()
	})

	client := agent.NewClient(conn)
	signers, err := client.Signers()
	if err != nil {
		debug("get ssh agent signers failed: %v", err)
		return nil
	}

	wrappers := make([]*sshSigner, 0, len(signers))
	for _, signer := range signers {
		wrappers = append(wrappers, &sshSigner{path: "ssh-agent", pubKey: signer.PublicKey(), signer: signer})
	}
	return wrappers
}

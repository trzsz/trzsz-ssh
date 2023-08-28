package tssh

import (
	"os"
	"time"

	"github.com/natefinch/npipe"
	"golang.org/x/crypto/ssh/agent"
)

// AGENT_PIPE_ID is the default pipe id for openssh ssh-agent on windows.
const AGENT_PIPE_ID = `\\.\pipe\openssh-ssh-agent`

func getAgentSigners() []*sshSigner {
	pipeId := AGENT_PIPE_ID
	// get enviroment override
	if socket := os.Getenv("SSH_AUTH_SOCK"); socket != "" {
		pipeId = AGENT_PIPE_ID
	}

	// test named pipe existance
	if _, err := os.Stat(pipeId); err != nil {
		if !os.IsNotExist(err) {
			debug("failed to access named pipe '%s': %v", pipeId, err)
		}
		return nil
	}

	// connect to named pipe
	conn, err := npipe.DialTimeout(pipeId, time.Second)
	if err != nil {
		debug("open ssh agent on named pipe '%s' failed: %v", pipeId, err)
		return nil
	}

	client := agent.NewClient(conn)
	cleanupAfterLogined = append(cleanupAfterLogined, func() {
		conn.Close()
	})

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

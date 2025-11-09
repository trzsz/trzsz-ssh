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
	"bufio"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

func enableWaypipe(args *sshArgs, ss *sshClientSession) error {
	if !ss.tty || strings.ToLower(getExOptionConfig(args, "EnableWaypipe")) != "yes" {
		return nil
	}
	if os.Getenv("WAYLAND_DISPLAY") == "" {
		warning("waypipe is not working since environment variable WAYLAND_DISPLAY is not set")
		return nil
	}

	token, err := generateRandomToken(8)
	if err != nil {
		return fmt.Errorf("generate random token for waypipe failed: %v", err)
	}

	clientSocket, err := runWaypipeClient(args, token)
	if err != nil {
		return fmt.Errorf("run waypipe client failed: %v", err)
	}

	cmd, serverSocket := getWaypipeServerCmd(args, ss.cmd, token)
	ss.cmd = cmd

	if err := remoteForwardSocket(ss.client, clientSocket, serverSocket); err != nil {
		return fmt.Errorf("remote forward socket for waypipe failed: %v", err)
	}

	return nil
}

func generateRandomToken(length int) (string, error) {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	token := make([]byte, length)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	for i := range token {
		token[i] = charset[int(token[i])%len(charset)]
	}
	return string(token), nil
}

func runWaypipeClient(args *sshArgs, token string) (string, error) {
	var buf strings.Builder
	clientPath := getExOptionConfig(args, "WaypipeClientPath")
	if clientPath == "" {
		clientPath = "waypipe"
	}
	buf.WriteString(clientPath)

	clientOption := getExOptionConfig(args, "WaypipeClientOption")
	if clientOption != "" {
		buf.WriteByte(' ')
		buf.WriteString(clientOption)
	}

	if !hasOptionSpecified(clientOption, "-c", "--compress") {
		buf.WriteString(" -c none")
	}

	if hasOptionSpecified(clientOption, "-s", "--socket") {
		warning("option -s --socket should not be specified in WaypipeClientOption: %s", clientOption)
	}
	clientSocket := fmt.Sprintf("/tmp/waypipe-client-%s.sock", token)
	buf.WriteString(" -s ")
	buf.WriteString(clientSocket)

	if hasOptionSpecified(clientOption, "client") {
		warning("option client should not be specified in WaypipeClientOption: %s", clientOption)
	}
	buf.WriteString(" client")

	command := buf.String()
	debug("waypipe client command: %s", command)

	argv, err := splitCommandLine(command)
	if err != nil || len(argv) == 0 {
		return "", fmt.Errorf("split waypipe client command [%s] failed: %v", command, err)
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", fmt.Errorf("stderr pipe for waypipe client failed: %v", err)
	}
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("start waypipe client [%s] failed: %v", command, err)
	}
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			output := scanner.Text()
			if strings.TrimSpace(output) == "" {
				continue
			}
			warning("waypipe client output error: %s", output)
		}
	}()
	onExitFuncs = append(onExitFuncs, func() {
		_ = cmd.Process.Signal(syscall.SIGINT)
	})

	return clientSocket, nil
}

func getWaypipeServerCmd(args *sshArgs, cmd, token string) (string, string) {
	var buf strings.Builder
	serverPath := getExOptionConfig(args, "WaypipeServerPath")
	if serverPath == "" {
		serverPath = "waypipe"
	}
	buf.WriteString(serverPath)

	serverOption := getExOptionConfig(args, "WaypipeServerOption")
	if serverOption != "" {
		buf.WriteByte(' ')
		buf.WriteString(serverOption)
	}

	if !hasOptionSpecified(serverOption, "-c", "--compress") {
		buf.WriteString(" -c none")
	}

	if hasOptionSpecified(serverOption, "--login-shell") {
		warning("option --login-shell should not be specified in WaypipeServerOption: %s", serverOption)
	}
	if cmd == "" {
		buf.WriteString(" --login-shell")
	}

	if !hasOptionSpecified(serverOption, "--unlink-socket") {
		buf.WriteString(" --unlink-socket")
	}

	if hasOptionSpecified(serverOption, "-s", "--socket") {
		warning("option -s --socket should not be specified in WaypipeServerOption: %s", serverOption)
	}
	serverSocket := fmt.Sprintf("/tmp/waypipe-server-%s.sock", token)
	buf.WriteString(" -s ")
	buf.WriteString(serverSocket)

	if hasOptionSpecified(serverOption, "--display") {
		warning("option --display should not be specified in WaypipeServerOption: %s", serverOption)
	}
	buf.WriteString(fmt.Sprintf(" --display wayland-%s", token))

	if hasOptionSpecified(serverOption, "server") {
		warning("option server should not be specified in WaypipeServerOption: %s", serverOption)
	}
	buf.WriteString(" server")

	if cmd != "" {
		buf.WriteByte(' ')
		buf.WriteString(cmd)
	}

	command := buf.String()
	debug("waypipe server command: %s", command)
	return command, serverSocket
}

func hasOptionSpecified(specifiedOptions string, optionPrefixs ...string) bool {
	for _, optionPrefix := range optionPrefixs {
		if strings.HasPrefix(specifiedOptions, optionPrefix) {
			return true
		}
		if strings.Contains(specifiedOptions, " "+optionPrefix) {
			return true
		}
	}
	return false
}

func remoteForwardSocket(client SshClient, clientSocket, serverSocket string) error {
	listener, err := client.Listen("unix", serverSocket)
	if err != nil {
		return err
	}
	go func() {
		defer func() { _ = listener.Close() }()
		for {
			remote, err := listener.Accept()
			if err == io.EOF {
				break
			}
			if err != nil {
				debug("waypipe remote accept failed: %v", err)
				continue
			}
			local, err := net.DialTimeout("unix", clientSocket, time.Second)
			if err != nil {
				debug("waypipe dial unix [%s] failed: %v", clientSocket, err)
				_ = remote.Close()
				continue
			}
			go netForward(local, remote)
		}
	}()
	return nil
}

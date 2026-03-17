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
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

func shouldSaveHost(args *sshArgs) bool {
	if args.NoSave {
		return false
	}
	return userConfig.autoSaveHost
}

var savedHosts = make(map[string]bool)
var savedHostsMutex sync.Mutex

func saveHostToConfig(args *sshArgs, sshConn *sshConnection) error {
	if !shouldSaveHost(args) {
		return nil
	}

	user, host, port := parseDestination(args.Destination)
	if host == "" {
		return fmt.Errorf("invalid destination: %s", args.Destination)
	}

	// Use port from -p argument if provided, otherwise use port from destination
	if args.Port > 0 {
		port = fmt.Sprintf("%d", args.Port)
	}

	// Prevent duplicate saves in the same session
	savedHostsMutex.Lock()
	defer savedHostsMutex.Unlock()

	saveKey := fmt.Sprintf("%s:%s:%s:%s", user, host, port, args.Group)
	if savedHosts[saveKey] {
		return nil // Already saved in this session
	}
	savedHosts[saveKey] = true

	debug("Attempting to save host: user=%s, host=%s, port=%s, group=%s", user, host, port, args.Group)

	existingHost := findHostInConfig(host)
	if existingHost != "" {
		// Check if configuration really needs to be updated
		if needsHostUpdate(existingHost, user, host, port, args.Group) {
			debug("Host '%s' configuration changed, updating", existingHost)
			return updateHostInConfig(existingHost, user, host, port, args.Group)
		} else {
			debug("Host '%s' configuration unchanged, skipping update", existingHost)
			return nil // Configuration unchanged, skip update
		}
	}

	debug("Host not found in config, adding new host")
	return addHostToConfig(user, host, port, args.Group)
}

func findHostInConfig(host string) string {
	loadSshConfig()

	for _, h := range userConfig.allHosts {
		// Check both Host and Alias for exact match
		if h.Host == host || h.Alias == host {
			return h.Alias
		}
	}

	// Also check directly in the config file to catch any edge cases
	configPath := getConfigPath()
	content, err := os.ReadFile(configPath)
	if err != nil {
		return ""
	}

	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, "Host ") {
			hostNames := strings.Fields(trimmedLine)[1:]
			for _, name := range hostNames {
				if name == host {
					return name
				}
			}
		}
		// Check HostName within this host block
		if strings.HasPrefix(trimmedLine, "HostName ") && i > 0 {
			hostValue := strings.TrimSpace(strings.TrimPrefix(trimmedLine, "HostName"))
			if hostValue == host {
				// Find the corresponding Host line above
				for j := i - 1; j >= 0; j-- {
					prevLine := strings.TrimSpace(lines[j])
					if strings.HasPrefix(prevLine, "Host ") {
						hostNames := strings.Fields(prevLine)[1:]
						if len(hostNames) > 0 {
							return hostNames[0]
						}
						break
					}
				}
			}
		}
	}

	return ""
}

func updateHostInConfig(alias, user, host, port, group string) error {
	configPath := getConfigPath()
	content, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %v", err)
	}

	lines := strings.Split(string(content), "\n")
	hostLine := -1
	hostEndLine := len(lines)
	inHostBlock := false

	// Preserve existing configuration values
	existingPort := ""
	existingUser := ""
	existingGroup := ""

	for i, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, "Host ") {
			if inHostBlock {
				hostEndLine = i
				break
			}
			hostNames := strings.Fields(trimmedLine)[1:]
			for _, name := range hostNames {
				if name == alias {
					hostLine = i
					inHostBlock = true
					break
				}
			}
		} else if inHostBlock {
			// Parse existing configuration within the host block
			if strings.HasPrefix(trimmedLine, "Port ") {
				existingPort = strings.TrimSpace(strings.TrimPrefix(trimmedLine, "Port"))
			} else if strings.HasPrefix(trimmedLine, "User ") {
				existingUser = strings.TrimSpace(strings.TrimPrefix(trimmedLine, "User"))
			} else if strings.HasPrefix(trimmedLine, "#!! GroupLabels ") {
				existingGroup = strings.TrimSpace(strings.TrimPrefix(trimmedLine, "#!! GroupLabels"))
			}
		}
	}

	if hostLine == -1 {
		return fmt.Errorf("host %s not found in config file", alias)
	}

	// Use new values if provided, otherwise keep existing ones
	finalPort := port
	if finalPort == "" {
		finalPort = existingPort
	}
	finalUser := user
	if finalUser == "" {
		finalUser = existingUser
	}
	finalGroup := group
	if finalGroup == "" {
		finalGroup = existingGroup
	}

	var newLines []string
	newLines = append(newLines, lines[:hostLine]...)
	newLines = append(newLines, fmt.Sprintf("Host %s", alias))
	newLines = append(newLines, fmt.Sprintf("    HostName %s", host))
	if finalUser != "" {
		newLines = append(newLines, fmt.Sprintf("    User %s", finalUser))
	}
	if finalPort != "" {
		newLines = append(newLines, fmt.Sprintf("    Port %s", finalPort))
	}
	if finalGroup != "" {
		newLines = append(newLines, fmt.Sprintf("    #!! GroupLabels %s", finalGroup))
	}
	newLines = append(newLines, lines[hostEndLine:]...)

	err = os.WriteFile(configPath, []byte(strings.Join(newLines, "\n")), 0600)
	if err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	userConfig.loadHosts = sync.Once{}

	fmt.Fprintf(os.Stderr, "\r\nHost %s updated in %s\r\n", alias, configPath)
	return nil
}

func addHostToConfig(user, host, port, group string) error {
	configPath := getConfigPath()

	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	file, err := os.OpenFile(configPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open config file: %v", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	writer.WriteString("\n")
	writer.WriteString(fmt.Sprintf("Host %s\n", host))
	writer.WriteString(fmt.Sprintf("    HostName %s\n", host))
	if user != "" {
		writer.WriteString(fmt.Sprintf("    User %s\n", user))
	}
	if port != "" {
		writer.WriteString(fmt.Sprintf("    Port %s\n", port))
	}
	if group != "" {
		writer.WriteString(fmt.Sprintf("    #!! GroupLabels %s\n", group))
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	userConfig.loadHosts = sync.Once{}

	fmt.Fprintf(os.Stderr, "\r\nHost %s added to %s\r\n", host, configPath)
	return nil
}

func getConfigPath() string {
	if userConfig.configPath != "" {
		return userConfig.configPath
	}
	return filepath.Join(userHomeDir, ".ssh", "config")
}

func loadSshConfig() {
	getAllHosts()
}

// getExistingHostConfig gets existing host configuration information
func getExistingHostConfig(alias string) *sshHost {
	loadSshConfig()

	for _, h := range userConfig.allHosts {
		if h.Alias == alias {
			return h
		}
	}
	return nil
}

// needsHostUpdate checks if host configuration needs to be updated
func needsHostUpdate(alias, user, host, port, group string) bool {
	existingConfig := getExistingHostConfig(alias)
	if existingConfig == nil {
		return true // Configuration does not exist, needs to be added
	}

	// Compare host address
	if existingConfig.Host != host {
		return true
	}

	// Compare username (if new value is not empty)
	if user != "" && existingConfig.User != user {
		return true
	}

	// Compare port (if new value is not empty)
	if port != "" && existingConfig.Port != port {
		return true
	}

	// Compare group labels (if new value is not empty)
	if group != "" && existingConfig.GroupLabels != group {
		return true
	}

	return false // Configuration is the same, no need to update
}

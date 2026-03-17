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
	"path/filepath"
	"strings"
)

func savePassword(args *sshArgs, password string) error {
	if password == "" {
		return nil
	}

	user, host, port := parseDestination(args.Destination)
	if host == "" {
		return fmt.Errorf("invalid destination: %s", args.Destination)
	}

	secret, err := encodeSecret([]byte(password))
	if err != nil {
		return fmt.Errorf("encode password failed: %v", err)
	}

	configPath := getPasswordConfigPath()
	if configPath == "" {
		// If no password save path is configured, save to SSH configuration file
		return savePasswordToConfig(args.Destination, secret)
	}

	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	var lines []string
	if isFileExist(configPath) {
		content, err := os.ReadFile(configPath)
		if err != nil {
			return fmt.Errorf("failed to read password config file: %v", err)
		}
		lines = strings.Split(string(content), "\n")
	}

	hostKey := host
	if port != "" {
		hostKey = fmt.Sprintf("%s:%s", host, port)
	}
	if user != "" {
		hostKey = fmt.Sprintf("%s@%s", user, hostKey)
	}

	found := false
	for i, line := range lines {
		if strings.HasPrefix(line, "Host "+hostKey) {
			if i+1 < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i+1]), "encPassword ") {
				lines[i+1] = fmt.Sprintf("    encPassword %s", secret)
				found = true
				break
			}
		}
	}

	if !found {
		if len(lines) > 0 && lines[len(lines)-1] != "" {
			lines = append(lines, "")
		}
		lines = append(lines, fmt.Sprintf("Host %s", hostKey))
		lines = append(lines, fmt.Sprintf("    encPassword %s", secret))
	}

	err = os.WriteFile(configPath, []byte(strings.Join(lines, "\n")), 0600)
	if err != nil {
		return fmt.Errorf("failed to write password config file: %v", err)
	}

	debug("Password saved for %s", hostKey)
	return nil
}

func savePasswordToConfig(alias string, secret string) error {
	configPath := getConfigPath()
	if !isFileExist(configPath) {
		return fmt.Errorf("SSH config file not found: %s", configPath)
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %v", err)
	}

	lines := strings.Split(string(content), "\n")
	hostLine := -1
	hostEndLine := len(lines)
	inHostBlock := false

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
		}
	}

	if hostLine == -1 {
		return fmt.Errorf("host %s not found in config file", alias)
	}

	passwordLine := -1
	for i := hostLine + 1; i < hostEndLine; i++ {
		trimmedLine := strings.TrimSpace(lines[i])
		if strings.HasPrefix(trimmedLine, "#!! encPassword ") {
			passwordLine = i
			break
		}
	}

	if passwordLine != -1 {
		lines[passwordLine] = fmt.Sprintf("    #!! encPassword %s", secret)
	} else {
		newLines := make([]string, 0, len(lines)+1)
		newLines = append(newLines, lines[:hostLine+1]...)
		newLines = append(newLines, fmt.Sprintf("    #!! encPassword %s", secret))
		newLines = append(newLines, lines[hostLine+1:]...)
		lines = newLines
	}

	err = os.WriteFile(configPath, []byte(strings.Join(lines, "\n")), 0600)
	if err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	debug("Password saved to SSH config for %s", alias)
	return nil
}

func getPasswordConfigPath() string {
	if userConfig.exConfigPath != "" {
		return userConfig.exConfigPath
	}
	return ""
}

// getExistingPassword gets existing password (uniformly decrypted to plaintext)
func getExistingPassword(destination string) string {
	user, host, port := parseDestination(destination)
	if host == "" {
		return ""
	}

	// Try to get from independent password configuration file
	configPath := getPasswordConfigPath()
	if configPath != "" {
		if password := getPasswordFromFile(configPath, user, host, port); password != "" {
			return password
		}
	}

	// Try to get from SSH configuration file
	if password := getPasswordFromConfig(host); password != "" {
		return password
	}

	return ""
}

// getPasswordFromFile gets password from independent password configuration file
func getPasswordFromFile(configPath, user, host, port string) string {
	if !isFileExist(configPath) {
		return ""
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		return ""
	}

	lines := strings.Split(string(content), "\n")
	hostKey := host
	if port != "" {
		hostKey = fmt.Sprintf("%s:%s", host, port)
	}
	if user != "" {
		hostKey = fmt.Sprintf("%s@%s", user, hostKey)
	}

	for i, line := range lines {
		if strings.HasPrefix(line, "Host "+hostKey) {
			if i+1 < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i+1]), "encPassword ") {
				encPassword := strings.TrimSpace(strings.TrimPrefix(lines[i+1], "encPassword "))
				if password, err := decodeSecret(encPassword); err == nil {
					return password
				}
			}
		}
	}

	return ""
}

// getPasswordFromConfig gets password from SSH configuration file
func getPasswordFromConfig(host string) string {
	configPath := getConfigPath()
	if !isFileExist(configPath) {
		return ""
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		return ""
	}

	lines := strings.Split(string(content), "\n")
	inHostBlock := false

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, "Host ") {
			hostNames := strings.Fields(trimmedLine)[1:]
			for _, name := range hostNames {
				if name == host {
					inHostBlock = true
					break
				}
			}
		} else if inHostBlock {
			if strings.HasPrefix(trimmedLine, "#!! encPassword ") {
				encPassword := strings.TrimSpace(strings.TrimPrefix(trimmedLine, "#!! encPassword "))
				if password, err := decodeSecret(encPassword); err == nil {
					return password
				}
			}
		}
	}

	return ""
}

// needsPasswordSave checks if password needs to be saved
func needsPasswordSave(destination, newPassword string) bool {
	existingPassword := getExistingPassword(destination)

	// Both are empty, no need to save
	if existingPassword == "" && newPassword == "" {
		return false
	}

	// One is empty and the other is not, need to save
	if (existingPassword == "") != (newPassword == "") {
		return true
	}

	// Both are not empty, compare actual values
	return existingPassword != newPassword
}

func savePasswordAfterLogin(args *sshArgs, password string) {
	if password == "" || args.NoSave {
		return
	}

	// Only save when password really needs to be saved
	if needsPasswordSave(args.Destination, password) {
		if err := savePassword(args, password); err != nil {
			// Only log error, don't interrupt connection
			warning("Failed to save password: %v", err)
		}
	}
}

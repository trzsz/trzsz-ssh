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
	"fmt"
	"os"
	"strings"
	"sync"
)

type removeHostResult struct {
	configUpdated   bool
	configPath      string
	configBlockDrop bool
	passwordUpdated bool
	passwordPath    string
}

type hostBlockRange struct {
	start   int
	end     int
	aliases []string
}

func execRemoveHost(args *sshArgs) (int, bool) {
	alias := strings.TrimSpace(args.RemoveHost)
	if alias == "" {
		toolsErrorExit("empty host alias")
	}

	if !args.Yes {
		if !isTerminal {
			toolsErrorExit("remove host [%s] requires --yes in non-interactive mode", alias)
		}
		if !promptBoolInput(fmt.Sprintf("Remove host [%s] from config and password store?", alias),
			"Enter Y or Yes to confirm removing the saved host and password.", false) {
			toolsWarn("RemoveHost", "cancelled removing host [%s]", alias)
			return 0, true
		}
	}

	result, err := removeHostArtifacts(alias)
	if err != nil {
		toolsErrorExit("remove host [%s] failed: %v", alias, err)
	}
	if !result.configUpdated && !result.passwordUpdated {
		toolsErrorExit("host [%s] not found in user config or password store", alias)
	}

	if result.configUpdated {
		if result.configBlockDrop {
			toolsSucc("RemoveHost", "removed host [%s] from %s", alias, result.configPath)
		} else {
			toolsSucc("RemoveHost", "removed alias [%s] from host entry in %s", alias, result.configPath)
		}
	}
	if result.passwordUpdated {
		toolsSucc("RemoveHost", "removed password for [%s] from %s", alias, result.passwordPath)
	}

	return 0, true
}

func removeHostArtifacts(alias string) (*removeHostResult, error) {
	result := &removeHostResult{}

	configPath := getConfigPath()
	configUpdated, blockDropped, err := removeAliasBlockFromFile(configPath, alias)
	if err != nil {
		return nil, err
	}
	if configUpdated {
		result.configUpdated = true
		result.configPath = configPath
		result.configBlockDrop = blockDropped
	}

	passwordPath := getPasswordConfigPath()
	if passwordPath == "" {
		passwordPath = configPath
	}
	passwordUpdated, _, err := removeAliasBlockFromFile(passwordPath, alias)
	if err != nil {
		return nil, err
	}
	if passwordUpdated {
		result.passwordUpdated = true
		result.passwordPath = passwordPath
	}

	if result.configUpdated || result.passwordUpdated {
		resetConfigCache()
	}

	return result, nil
}

func removeAliasBlockFromFile(path, alias string) (bool, bool, error) {
	if path == "" || !isFileExist(path) {
		return false, false, nil
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return false, false, fmt.Errorf("read config file [%s] failed: %v", path, err)
	}

	updated, blockDropped, err := removeAliasBlockContent(string(content), alias)
	if err != nil {
		return false, false, fmt.Errorf("remove host [%s] from [%s] failed: %v", alias, path, err)
	}
	if updated == string(content) {
		return false, false, nil
	}

	if err := os.WriteFile(path, []byte(updated), 0600); err != nil {
		return false, false, fmt.Errorf("write config file [%s] failed: %v", path, err)
	}
	return true, blockDropped, nil
}

func removeAliasBlockContent(content, alias string) (string, bool, error) {
	lines := strings.Split(content, "\n")
	block, found := findHostBlockByAlias(lines, alias)
	if !found {
		return content, false, nil
	}

	if len(block.aliases) == 0 {
		return "", false, fmt.Errorf("invalid host block for alias %s", alias)
	}

	if len(block.aliases) == 1 {
		lines = append(lines[:block.start], lines[block.end:]...)
		return trimExtraBlankLines(lines), true, nil
	}

	var aliases []string
	for _, name := range block.aliases {
		if name != alias {
			aliases = append(aliases, name)
		}
	}
	if len(aliases) == len(block.aliases) {
		return content, false, nil
	}

	lines[block.start] = rebuildHostLine(lines[block.start], aliases)
	return strings.Join(lines, "\n"), false, nil
}

func findHostBlockByAlias(lines []string, alias string) (*hostBlockRange, bool) {
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "Host ") {
			continue
		}

		aliases := strings.Fields(trimmed)[1:]
		matched := false
		for _, name := range aliases {
			if name == alias {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}

		end := len(lines)
		for j := i + 1; j < len(lines); j++ {
			if strings.HasPrefix(strings.TrimSpace(lines[j]), "Host ") {
				end = j
				break
			}
		}
		return &hostBlockRange{start: i, end: end, aliases: aliases}, true
	}
	return nil, false
}

func rebuildHostLine(line string, aliases []string) string {
	trimmed := strings.TrimLeft(line, " \t")
	indent := line[:len(line)-len(trimmed)]
	return fmt.Sprintf("%sHost %s", indent, strings.Join(aliases, " "))
}

func trimExtraBlankLines(lines []string) string {
	start := 0
	for start < len(lines) && strings.TrimSpace(lines[start]) == "" {
		start++
	}
	end := len(lines)
	for end > start && strings.TrimSpace(lines[end-1]) == "" {
		end--
	}

	var cleaned []string
	prevBlank := false
	for _, line := range lines[start:end] {
		blank := strings.TrimSpace(line) == ""
		if blank && prevBlank {
			continue
		}
		cleaned = append(cleaned, line)
		prevBlank = blank
	}

	return strings.Join(cleaned, "\n")
}

func resetConfigCache() {
	userConfig.loadConfig = sync.Once{}
	userConfig.loadExConfig = sync.Once{}
	userConfig.loadHosts = sync.Once{}
	userConfig.config = nil
	userConfig.sysConfig = nil
	userConfig.exConfig = nil
	userConfig.allHosts = nil
	userConfig.wildcardPatterns = nil
}

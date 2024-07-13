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
	"regexp"
	"strings"
)

type sshEnv struct {
	name  string
	value string
}

func getSendEnvs(args *sshArgs) ([]*sshEnv, error) {
	envSet := make(map[string]struct{})
	for _, env := range getAllOptionConfigSplits(args, "SendEnv") {
		if len(env) > 0 {
			envSet[env] = struct{}{}
		}
	}
	if len(envSet) == 0 {
		return nil, nil
	}

	var buf strings.Builder
	for env := range envSet {
		if buf.Len() > 0 {
			buf.WriteRune('|')
		}
		buf.WriteString("(^")
		for _, c := range env {
			switch c {
			case '*':
				buf.WriteString(".*")
			case '?':
				buf.WriteRune('.')
			case '(', ')', '[', ']', '{', '}', '.', '+', ',', '-', '^', '$', '|', '\\':
				buf.WriteRune('\\')
				buf.WriteRune(c)
			default:
				buf.WriteRune(c)
			}
		}
		buf.WriteString("$)")
	}
	expr := buf.String()
	debug("send env regexp: %s", expr)

	re, err := regexp.Compile(expr)
	if err != nil {
		return nil, fmt.Errorf("compile SendEnv regexp failed: %v", err)
	}

	var envs []*sshEnv
	for _, env := range os.Environ() {
		var name string
		pos := strings.IndexRune(env, '=')
		if pos < 0 {
			name = strings.TrimSpace(env)
		} else {
			name = strings.TrimSpace(env[:pos])
		}
		if !re.MatchString(name) {
			continue
		}
		var value string
		if pos >= 0 {
			value = strings.TrimSpace(env[pos+1:])
		}
		envs = append(envs, &sshEnv{name, value})
	}
	return envs, nil
}

func getSetEnvs(args *sshArgs) ([]*sshEnv, error) {
	setEnvs := getOptionConfigSplits(args, "SetEnv")
	if len(setEnvs) == 0 {
		return nil, nil
	}
	var envs []*sshEnv
	for _, token := range setEnvs {
		pos := strings.IndexRune(token, '=')
		if pos < 0 {
			return nil, fmt.Errorf("invalid SetEnv: %s", token)
		}
		name := strings.TrimSpace(token[:pos])
		if name == "" {
			return nil, fmt.Errorf("invalid SetEnv: %s", token)
		}
		value := strings.TrimSpace(token[pos+1:])
		envs = append(envs, &sshEnv{name, value})
	}
	return envs, nil
}

func sendAndSetEnv(args *sshArgs, session SshSession) (string, error) {
	sendEnvs, err := getSendEnvs(args)
	if err != nil {
		return "", err
	}
	for _, env := range sendEnvs {
		if err := session.Setenv(env.name, env.value); err != nil {
			debug("send env failed: %s = \"%s\"", env.name, env.value)
		} else {
			debug("send env success: %s = \"%s\"", env.name, env.value)
		}
	}

	setEnvs, err := getSetEnvs(args)
	if err != nil {
		return "", err
	}
	var term string
	for _, env := range setEnvs {
		if env.name == "TERM" {
			term = env.value
		}
		if err := session.Setenv(env.name, env.value); err != nil {
			debug("set env failed: %s = \"%s\"", env.name, env.value)
		} else {
			debug("set env success: %s = \"%s\"", env.name, env.value)
		}
	}

	return term, nil
}

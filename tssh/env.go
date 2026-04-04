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
	"regexp"
	"strings"
)

type sshEnv struct {
	name  string
	value string
}

type sendEnvRule struct {
	pattern string
	negate  bool
	re      *regexp.Regexp
}

func getSendEnvs(args *sshArgs) ([]*sshEnv, error) {
	var rules []sendEnvRule
	for _, env := range getAllOptionConfigSplits(args, "SendEnv") {
		if len(env) == 0 {
			continue
		}

		rule := sendEnvRule{}
		if strings.HasPrefix(env, "-") {
			rule.negate = true
			rule.pattern = env[1:]
		} else {
			rule.pattern = env
		}
		if rule.pattern == "" {
			continue
		}

		var buf strings.Builder
		buf.WriteByte('^')
		buf.WriteString(wildcardToRegexp(rule.pattern))
		buf.WriteByte('$')

		expr := buf.String()
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("compile SendEnv [%s] regexp [%s] failed: %v", env, expr, err)
		}
		rule.re = re
		rules = append(rules, rule)
	}

	if len(rules) == 0 {
		return nil, nil
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

		for _, rule := range rules {
			if rule.re.MatchString(name) {
				if rule.negate {
					debug("ignored env: %s (matches rule: -%s)", name, rule.pattern)
				} else {
					debug("sending env: %s (matches rule: %s)", name, rule.pattern)
					var value string
					if pos >= 0 {
						value = strings.TrimSpace(env[pos+1:])
					}
					envs = append(envs, &sshEnv{name, value})
				}
				break
			}
		}
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

	if term == "" {
		term = os.Getenv("TERM")
		if term == "" {
			term = "xterm-256color"
		}
	}

	return term, nil
}

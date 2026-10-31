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

	"github.com/stretchr/testify/assert"
)

func TestSendEnvRulesMatch(t *testing.T) {
	assert := assert.New(t)
	oriUserConfig := userConfig
	userConfig = &tsshConfig{}
	defer func() { userConfig = oriUserConfig }()

	args := &sshArgs{Destination: "myhost"}
	args.Option.options = map[string][]string{"sendenv": {"LC_* -LC_ALL LANG"}}
	rules, err := getSendEnvRules(args)
	assert.Nil(err)
	assert.Len(rules, 3)

	rule := rules.match("LC_ALL")
	assert.NotNil(rule)
	assert.Equal("LC_*", rule.pattern)
	assert.False(rule.negate)
	assert.True(rules.permit("LC_ALL"))

	rule = rules.match("LANG")
	assert.NotNil(rule)
	assert.Equal("LANG", rule.pattern)
	assert.True(rules.permit("LANG"))

	assert.Nil(rules.match("TERM"))
	assert.False(rules.permit("TERM"))

	args.Option.options = map[string][]string{"sendenv": {"-LC_ALL LC_*"}}
	rules, err = getSendEnvRules(args)
	assert.Nil(err)
	rule = rules.match("LC_ALL")
	assert.NotNil(rule)
	assert.True(rule.negate)
	assert.False(rules.permit("LC_ALL"))
	assert.True(rules.permit("LC_TIME"))

	assert.Nil(sendEnvRules(nil).match("LANG"))
	assert.False(sendEnvRules(nil).permit("LANG"))
}

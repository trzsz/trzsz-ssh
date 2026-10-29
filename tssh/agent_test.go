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

func TestIsAgentForwardEnabled(t *testing.T) {
	assert := assert.New(t)
	oriUserConfig := userConfig
	userConfig = &tsshConfig{}
	defer func() { userConfig = oriUserConfig }()

	withOption := func(value string) *sshArgs {
		args := &sshArgs{Destination: "myhost"}
		args.Option.options = map[string][]string{"forwardagent": {value}}
		return args
	}

	assert.False(isAgentForwardEnabled(&sshArgs{Destination: "myhost"}))
	assert.True(isAgentForwardEnabled(&sshArgs{Destination: "myhost", ForwardAgent: true}))
	assert.False(isAgentForwardEnabled(&sshArgs{Destination: "myhost", ForwardAgent: true, NoForwardAgent: true}))
	assert.True(isAgentForwardEnabled(withOption("yes")))
	assert.True(isAgentForwardEnabled(withOption("Yes")))
	assert.False(isAgentForwardEnabled(withOption("no")))
	args := withOption("yes")
	args.NoForwardAgent = true
	assert.False(isAgentForwardEnabled(args))
}

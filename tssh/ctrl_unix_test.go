//go:build !windows

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
	"io"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureWarnings runs fn with os.Stderr redirected and returns what was written to it.
func captureWarnings(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	oldStderr, oldWidth, oldWarning := os.Stderr, currentTerminalWidth.Load(), enableWarningLogging
	os.Stderr, enableWarningLogging = w, true
	currentTerminalWidth.Store(0)
	defer func() {
		os.Stderr, enableWarningLogging = oldStderr, oldWarning
		currentTerminalWidth.Store(oldWidth)
	}()
	fn()
	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out)
}

func TestWarnObsoleteCtrlExpect(t *testing.T) {
	oldUserConfig, oldUserHomeDir := userConfig, userHomeDir
	defer func() {
		userConfig, userHomeDir = oldUserConfig, oldUserHomeDir
		ctrlExpectObsoleteOnce = sync.Once{}
	}()
	userConfig, userHomeDir, ctrlExpectObsoleteOnce = &tsshConfig{}, t.TempDir(), sync.Once{}

	withoutCtrl := &sshArgs{Destination: "test-host"}
	assert.Empty(t, captureWarnings(t, func() { warnObsoleteCtrlExpect(withoutCtrl) }))

	withCtrl := &sshArgs{Destination: "test-host"}
	withCtrl.Option.options = map[string][]string{"ctrlexpectcount": {"1"}}
	out := captureWarnings(t, func() { warnObsoleteCtrlExpect(withCtrl) })
	assert.Contains(t, out, "Warning: the Ctrl prefixed automated interaction options")
	assert.Contains(t, out, "ExpectCount / ExpectPattern")

	// only once per process
	assert.Empty(t, captureWarnings(t, func() { warnObsoleteCtrlExpect(withCtrl) }))
}

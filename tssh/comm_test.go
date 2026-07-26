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

func TestConvertSshTime(t *testing.T) {
	assert := assert.New(t)
	assertTimeEqual := func(time string, expected uint32) {
		t.Helper()
		seconds, err := convertSshTime(time)
		assert.Nil(err)
		assert.Equal(expected, seconds)
	}
	assertTimeEqual("0", 0)
	assertTimeEqual("0s", 0)
	assertTimeEqual("0W", 0)
	assertTimeEqual("1", 1)
	assertTimeEqual("1S", 1)
	assertTimeEqual("90m", 5400)
	assertTimeEqual("1h30m", 5400)
	assertTimeEqual("2d", 172800)
	assertTimeEqual("1w", 604800)
	assertTimeEqual("1W2d3h4m5", 788645)

	assertTimeEqual("10S", 10)
	assertTimeEqual("2M", 120)
	assertTimeEqual("2H", 7200)
	assertTimeEqual("2D", 172800)
	assertTimeEqual("2W", 1209600)
	assertTimeEqual("2d3h15m10s", 2*86400+3*3600+15*60+10)
	assertTimeEqual("4294967295", 4294967295)

	assertTimeError := func(input string, errMsgSubstring string) {
		t.Helper()
		_, err := convertSshTime(input)
		assert.NotNil(err)
		assert.Contains(err.Error(), errMsgSubstring)
	}
	assertTimeError("", "empty")
	assertTimeError("abc", "invalid")
	assertTimeError("10x", "invalid")
	assertTimeError("10m5y", "invalid")
	assertTimeError("9999999999h", "overflow")
	assertTimeError("4294967296s", "overflow")
}

func TestFormatSshTime(t *testing.T) {
	tests := []struct {
		name     string
		seconds  uint32
		expected string
	}{
		{
			name:     "Zero seconds",
			seconds:  0,
			expected: "0s",
		},
		{
			name:     "Only seconds",
			seconds:  45,
			expected: "45s",
		},
		{
			name:     "Only minutes",
			seconds:  120, // 2m
			expected: "2m",
		},
		{
			name:     "Weeks and seconds (skip days, hours, mins)",
			seconds:  7*24*60*60 + 2, // 1w + 2s
			expected: "1w2s",
		},
		{
			name:     "Days and minutes (skip hours and seconds)",
			seconds:  24*60*60 + 120, // 1d + 2m
			expected: "1d2m",
		},
		{
			name:     "All units combined",
			seconds:  7*24*60*60 + 2*24*60*60 + 3*60*60 + 4*60 + 5, // 1w 2d 3h 4m 5s
			expected: "1w2d3h4m5s",
		},
		{
			name:     "More than one week with overflow-like logic",
			seconds:  10 * 24 * 60 * 60, // 10 days = 1w 3d
			expected: "1w3d",
		},
		{
			name:     "Weeks, hours, and seconds (skip days and mins)",
			seconds:  2*7*24*60*60 + 5*60*60 + 30,
			expected: "2w5h30s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatSshTime(tt.seconds)
			if result != tt.expected {
				t.Errorf("formatSshTime(%d) = %q; want %q", tt.seconds, result, tt.expected)
			}
		})
	}
}

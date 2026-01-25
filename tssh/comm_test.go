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

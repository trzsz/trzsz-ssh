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

func TestParseTsshdPortRanges(t *testing.T) {
	enableWarning := enableWarningLogging
	enableWarningLogging = false
	defer func() { enableWarningLogging = enableWarning }()

	assert := assert.New(t)
	assert.Equal([][2]uint16{{22, 22}}, parseTsshdPortRanges("22"))
	assert.Equal([][2]uint16{{100, 102}}, parseTsshdPortRanges("100-102"))
	assert.Equal([][2]uint16{{200, 202}}, parseTsshdPortRanges("200 - 202"))
	assert.Equal([][2]uint16{{10, 10}, {20, 20}, {30, 30}}, parseTsshdPortRanges("10 20 30"))
	assert.Equal([][2]uint16{{1, 3}, {5, 5}, {7, 9}, {11, 11}}, parseTsshdPortRanges("1-3 5,7 - 9 11"))
	assert.Equal([][2]uint16{{1, 2}, {3, 4}, {5, 5}}, parseTsshdPortRanges("1-2,3-4 5"))
	assert.Equal([][2]uint16{{10, 12}, {15, 15}}, parseTsshdPortRanges("  10\t-\t12  , 15 "))
	assert.Equal([][2]uint16{{50, 50}}, parseTsshdPortRanges("50-50"))
	assert.Equal([][2]uint16{{10, 10}, {20, 20}}, parseTsshdPortRanges("10,,20"))
	assert.Equal([][2]uint16(nil), parseTsshdPortRanges("0,70000,abc"))
	assert.Equal([][2]uint16(nil), parseTsshdPortRanges("100-50"))
	assert.Equal([][2]uint16(nil), parseTsshdPortRanges("-"))
	assert.Equal([][2]uint16(nil), parseTsshdPortRanges("- 10"))
	assert.Equal([][2]uint16(nil), parseTsshdPortRanges("10 -"))
	assert.Equal([][2]uint16{{1, 3}, {7, 7}}, parseTsshdPortRanges("1-3,abc,5 - 4,7"))
	assert.Equal([][2]uint16(nil), parseTsshdPortRanges(""))
	assert.Equal([][2]uint16(nil), parseTsshdPortRanges("8000-9000-10000"))
	assert.Equal([][2]uint16(nil), parseTsshdPortRanges("8000-"))
	assert.Equal([][2]uint16(nil), parseTsshdPortRanges("-9000"))
	assert.Equal([][2]uint16{{10, 12}}, parseTsshdPortRanges("10 - 12 - 15"))
	assert.Equal([][2]uint16{{1, 65535}}, parseTsshdPortRanges("1-65535"))
	assert.Equal([][2]uint16{{10, 10}, {10, 10}, {10, 10}}, parseTsshdPortRanges("10 10 10"))
	assert.Equal([][2]uint16{{20, 25}, {22, 23}}, parseTsshdPortRanges("20-25 22-23"))
	assert.Equal([][2]uint16(nil), parseTsshdPortRanges("10 - 0"))
	assert.Equal([][2]uint16(nil), parseTsshdPortRanges("10 - - 11"))
	assert.Equal([][2]uint16{{10, 11}}, parseTsshdPortRanges("10 - 11 -"))
}

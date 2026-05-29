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

import "testing"

func TestParseUdpReconnectExitKey(t *testing.T) {
	tests := []struct {
		input   string
		wantKey byte // 0 means disabled.
	}{
		{"", 0x04},
		{"Ctrl+D", 0x04},
		{"ctrl+d", 0x04},
		{"CTRL+D", 0x04},
		{"Ctrl+C", 0x03},
		{"ctrl+c", 0x03},
		{"CTRL+C", 0x03},
		{"Ctrl+Q", 0x11},
		{"ctrl+q", 0x11},
		{"^q", 0x11},
		{"^Q", 0x11},
		{"Ctrl+X", 0x18},
		{"ctrl+x", 0x18},
		{"^x", 0x18},
		{"^X", 0x18},
		{"q", 0x04},
		{".", 0x04},
		{"none", 0},
		{"NONE", 0},
		{"OFF", 0x04},
		{"disable", 0x04},
		{"disabled", 0x04},
		{"Ctrl+A", 0x04},
		{"^A", 0x04},
		{"Ctrl+1", 0x04},
		{"^1", 0x04},
		{"abc", 0x04},
		{"  Ctrl+X  ", 0x18},
		{"  ^X  ", 0x18},
	}
	for _, tt := range tests {
		if gotKey := parseUdpReconnectExitKey(tt.input); gotKey != tt.wantKey {
			t.Errorf("parseUdpReconnectExitKey(%q) = 0x%02x, want 0x%02x", tt.input, gotKey, tt.wantKey)
		}
	}
}

func TestUdpReconnectExitKeyName(t *testing.T) {
	tests := []struct {
		key  byte
		want string
	}{
		{0x04, "Ctrl+D"},
		{0x03, "Ctrl+C"},
		{0x18, "Ctrl+X"},
	}
	for _, tt := range tests {
		if got := udpReconnectExitKeyName(tt.key); got != tt.want {
			t.Errorf("udpReconnectExitKeyName(0x%02x) = %q, want %q", tt.key, got, tt.want)
		}
	}
}

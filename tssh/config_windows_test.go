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
	"reflect"
	"testing"

	"github.com/trzsz/ssh_config"
)

func TestSplitConfigValuePreservesWindowsPaths(t *testing.T) {
	value := `C:\Users\LENVO/.ssh/known_hosts C:\Users\LENVO/.ssh/known_hosts2`
	got, err := ssh_config.SplitConfigValue("UserKnownHostsFile", value)
	if err != nil {
		t.Fatalf("split Windows config value: %v", err)
	}
	want := []string{`C:\Users\LENVO/.ssh/known_hosts`, `C:\Users\LENVO/.ssh/known_hosts2`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Windows config paths = %#v, want %#v", got, want)
	}
}

func TestSplitConfigValueWindowsQuotedPath(t *testing.T) {
	value := `"C:\Users\LEN VO\.ssh\known_hosts" 'C:\Users\LEN VO\.ssh\known_hosts2'`
	got, err := ssh_config.SplitConfigValue("UserKnownHostsFile", value)
	if err != nil {
		t.Fatalf("split quoted Windows config value: %v", err)
	}
	want := []string{`C:\Users\LEN VO\.ssh\known_hosts`, `C:\Users\LEN VO\.ssh\known_hosts2`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("quoted Windows config path = %#v, want %#v", got, want)
	}
}

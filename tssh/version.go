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
	dbg "runtime/debug"
	"strings"
)

const kTsshVersion = "0.1.23"

// buildTag stores the version tag injected at build time via -ldflags.
var buildTag = ""

func getTsshVersion() string {
	var version strings.Builder
	version.WriteString("trzsz ssh ")
	version.WriteString(kTsshVersion)

	if buildTag != "" {
		version.WriteByte('(')
		version.WriteString(buildTag)
		version.WriteByte(')')
	}

	if info, ok := dbg.ReadBuildInfo(); ok {
		var vcs, revision, modified string
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs":
				vcs = setting.Value
			case "vcs.revision":
				revision = setting.Value
			case "vcs.modified":
				modified = setting.Value
			}
		}

		if vcs == "git" {
			if revision != "" {
				version.WriteByte('-')
				version.WriteString(revision[:min(7, len(revision))])
				if strings.ToLower(modified) == "true" {
					version.WriteString("-m")
				}
			}
		}
	}

	return version.String()
}

func printVersionShort() int {
	fmt.Println("trzsz ssh " + kTsshVersion)
	return 0
}

func printVersionDetailed() (int, bool) {
	fmt.Println(getTsshVersion())
	return 0, true
}

/*
MIT License

Copyright (c) 2023-2026 The Trzsz SSH Authors.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, sublicense, and/or sell
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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
)

func TestFileManagerPaneOrdersDirectoriesFirst(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("b"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "a-dir"), 0700); err != nil {
		t.Fatal(err)
	}

	pane := newFileManagerPane("Local", &localFileManagerFS{}, dir)
	if err := pane.refresh(); err != nil {
		t.Fatal(err)
	}
	if len(pane.entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(pane.entries))
	}
	if pane.entries[0].Name != "a-dir" || !pane.entries[0].IsDir {
		t.Fatalf("first entry = %#v, want directory a-dir", pane.entries[0])
	}
	if pane.entries[1].Name != "b.txt" || pane.entries[1].IsDir {
		t.Fatalf("second entry = %#v, want file b.txt", pane.entries[1])
	}
}

func TestFileManagerCopyFileBetweenLocalFilesystems(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "release.txt")
	if err := os.WriteFile(srcPath, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}

	fs := &localFileManagerFS{}
	dstPath := filepath.Join(dstDir, "release.txt")
	if err := copyFileManagerPath(fs, fs, srcPath, dstPath, fileTransferOptions{}); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "hello" {
		t.Fatalf("content = %q, want hello", string(content))
	}
}

func TestFileManagerCopyDirectoryBetweenLocalFilesystems(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()
	nested := filepath.Join(srcDir, "logs", "app.log")
	if err := os.MkdirAll(filepath.Dir(nested), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nested, []byte("log"), 0600); err != nil {
		t.Fatal(err)
	}

	fs := &localFileManagerFS{}
	target := filepath.Join(dstDir, "backup")
	if err := copyFileManagerPath(fs, fs, srcDir, target, fileTransferOptions{}); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(filepath.Join(target, "logs", "app.log"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "log" {
		t.Fatalf("content = %q, want log", string(content))
	}
}

func TestFileManagerPadAndTruncateUseDisplayWidth(t *testing.T) {
	padded := padRight("你好", 6)
	if ansi.StringWidth(padded) != 6 {
		t.Fatalf("padded width = %d, want 6", ansi.StringWidth(padded))
	}

	truncated := truncateText("你好世界", 5)
	if ansi.StringWidth(truncated) > 5 {
		t.Fatalf("truncated width = %d, want <= 5", ansi.StringWidth(truncated))
	}
}

func TestRenderFileManagerKeepsLineWidthWithWideCharacters(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "你好-world.txt"), []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rocket-🚀.txt"), []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}

	fs := &localFileManagerFS{}
	model, err := newFileManagerModel(fs, fs, dir, dir)
	if err != nil {
		t.Fatal(err)
	}

	view := renderFileManager(model)
	for _, line := range strings.Split(view, "\r\n") {
		if line == "" || strings.HasPrefix(line, "\x1b[H") {
			continue
		}
		if ansi.StringWidth(line) > 100 {
			t.Fatalf("line width = %d, want <= 100, line = %q", ansi.StringWidth(line), line)
		}
	}
}

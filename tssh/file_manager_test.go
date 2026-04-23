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

func TestFileManagerPaneFuzzyFilter(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"release.tar.gz", "README.md", "server.log"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
	}

	pane := newFileManagerPane("Local", &localFileManagerFS{}, dir)
	if err := pane.refresh(); err != nil {
		t.Fatal(err)
	}
	pane.setFilter("rtg")
	if len(pane.filtered) != 1 {
		t.Fatalf("filtered = %d, want 1", len(pane.filtered))
	}
	if pane.filtered[0].Name != "release.tar.gz" {
		t.Fatalf("filtered[0] = %q, want release.tar.gz", pane.filtered[0].Name)
	}
	entry, ok := pane.currentEntry()
	if !ok || entry.Name != "release.tar.gz" {
		t.Fatalf("current entry = %#v, %v", entry, ok)
	}
}

func TestFileManagerPaneClearFilterRestoresEntries(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"alpha.txt", "beta.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
	}

	pane := newFileManagerPane("Local", &localFileManagerFS{}, dir)
	if err := pane.refresh(); err != nil {
		t.Fatal(err)
	}
	pane.setFilter("alpha")
	pane.clearFilter()
	if len(pane.filtered) != len(pane.entries) {
		t.Fatalf("filtered = %d, want %d", len(pane.filtered), len(pane.entries))
	}
	if pane.filter != "" {
		t.Fatalf("filter = %q, want empty", pane.filter)
	}
}

func TestFileManagerEscClearsFilterBeforeQuit(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "alpha.txt"), []byte("alpha"), 0600); err != nil {
		t.Fatal(err)
	}

	fs := &localFileManagerFS{}
	model, err := newFileManagerModel(fs, fs, dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	model.activePane().setFilter("alpha")

	if !isFileManagerClearFilterKey(model, []byte{keyESC}) {
		t.Fatalf("expected Esc to clear filter before quit")
	}
	model.activePane().clearFilter()
	if isFileManagerClearFilterKey(model, []byte{keyESC}) {
		t.Fatalf("expected Esc not to clear filter when filter is empty")
	}
}

func TestFileManagerSearchEscClearsFilter(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "alpha.txt"), []byte("alpha"), 0600); err != nil {
		t.Fatal(err)
	}

	fs := &localFileManagerFS{}
	model, err := newFileManagerModel(fs, fs, dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	model.searching = true
	model.activePane().setFilter("alpha")

	handleFileManagerSearchKey(model, []byte{keyESC})
	if model.searching {
		t.Fatalf("expected search mode to end")
	}
	if model.activePane().filter != "" {
		t.Fatalf("expected filter to be cleared, got %q", model.activePane().filter)
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

func TestRenderFileManagerPaneWrapsLinesWithStableWidth(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "你好-world.txt"), []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}

	fs := &localFileManagerFS{}
	pane := newFileManagerPane("Local", fs, dir)
	if err := pane.refresh(); err != nil {
		t.Fatal(err)
	}

	const width = 42
	lines := renderFileManagerPane(pane, width, 5, true, newFileManagerTheme())
	for _, line := range lines {
		if ansi.StringWidth(line) != width {
			t.Fatalf("line width = %d, want %d, line = %q", ansi.StringWidth(line), width, line)
		}
	}
}

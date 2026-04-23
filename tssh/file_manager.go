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
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/x/ansi"
)

func execFileManager(sshConn *sshConnection) int {
	if err := runFileManager(sshConn.client); err != nil {
		warning("file manager failed: %v", err)
		return kExitCodeTrzRunError
	}
	return 0
}

func runFileManager(client SshClient) error {
	localFS := &localFileManagerFS{}
	remoteFS, err := newSftpFileManagerFS(client)
	if err != nil {
		return err
	}
	defer remoteFS.Close()

	localDir, err := os.Getwd()
	if err != nil {
		return err
	}

	remoteDir := "."
	if cwd, err := remoteFS.client.Getwd(); err == nil && cwd != "" {
		remoteDir = cwd
	}

	model, err := newFileManagerModel(localFS, remoteFS, localDir, remoteDir)
	if err != nil {
		return err
	}

	state, err := makeStdinRaw()
	if err != nil {
		return err
	}
	defer resetStdin(state)
	hideCursor(os.Stderr)
	defer showCursor(os.Stderr)

	buf := make([]byte, 32)
	for {
		_, _ = os.Stderr.WriteString(renderFileManager(model))
		n, err := os.Stdin.Read(buf)
		if err != nil {
			return err
		}
		key := buf[:n]
		switch {
		case isFileManagerQuitKey(key):
			model.cancelled = true
			_, _ = os.Stderr.WriteString("\x1b[H\x1b[2J")
			return nil
		case len(key) == 1 && key[0] == '\t':
			model.switchPane()
		case isFileManagerMoveDownKey(key):
			model.activePane().move(1)
		case isFileManagerMoveUpKey(key):
			model.activePane().move(-1)
		case len(key) == 1 && (key[0] == keyEnter || key[0] == '\n'):
			if err := model.activePane().enter(); err != nil {
				model.message = err.Error()
			}
		case len(key) == 1 && (key[0] == '\x7f' || key[0] == keyCtrlH):
			if err := model.activePane().back(); err != nil {
				model.message = err.Error()
			}
		case len(key) == 1 && key[0] == ' ':
			model.activePane().toggleCurrent()
		case len(key) == 1 && (key[0] == 'r' || key[0] == 'R'):
			if err := model.local.refresh(); err != nil {
				model.message = err.Error()
			}
			if err := model.remote.refresh(); err != nil {
				model.message = err.Error()
			}
		case len(key) == 1 && key[0] == 'U':
			if err := runFileManagerTransfer(model, true); err != nil {
				model.message = err.Error()
			}
		case len(key) == 1 && key[0] == 'D':
			if err := runFileManagerTransfer(model, false); err != nil {
				model.message = err.Error()
			}
		}
	}
}

func runFileManagerTransfer(model *fileManagerModel, upload bool) error {
	lastRender := time.Time{}
	progress := func(event fileTransferProgress) {
		now := time.Now()
		if now.Sub(lastRender) < 120*time.Millisecond && event.Done < event.Total {
			return
		}
		lastRender = now
		model.message = formatFileTransferProgress(event)
		_, _ = os.Stderr.WriteString(renderFileManager(model))
	}
	if upload {
		return model.upload(progress)
	}
	return model.download(progress)
}

func isFileManagerQuitKey(key []byte) bool {
	return len(key) == 1 && (key[0] == 'q' || key[0] == 'Q' || key[0] == keyESC || key[0] == keyCtrlC)
}

func isFileManagerMoveDownKey(key []byte) bool {
	return len(key) == 1 && (key[0] == 'j' || key[0] == 'J') ||
		len(key) == 3 && key[0] == keyESC && key[1] == '[' && key[2] == 'B'
}

func isFileManagerMoveUpKey(key []byte) bool {
	return len(key) == 1 && (key[0] == 'k' || key[0] == 'K') ||
		len(key) == 3 && key[0] == keyESC && key[1] == '[' && key[2] == 'A'
}

func renderFileManager(model *fileManagerModel) string {
	width, height, err := getTerminalSize()
	if err != nil || width <= 0 {
		width = 100
	}
	if width < 60 {
		width = 60
	}
	if height < 12 {
		height = 24
	}
	separator := " | "
	separatorWidth := ansi.StringWidth(separator)
	paneWidth := (width - separatorWidth) / 2
	rightWidth := width - separatorWidth - paneWidth
	pageSize := height - 7
	if pageSize < 5 {
		pageSize = 5
	}

	left := renderFileManagerPane(model.local, paneWidth, pageSize, model.active == fileManagerLocalPane)
	right := renderFileManagerPane(model.remote, rightWidth, pageSize, model.active == fileManagerRemotePane)
	lines := make([]string, 0, pageSize+6)
	lines = append(lines, "\x1b[H\x1b[2J")
	for i := 0; i < len(left) || i < len(right); i++ {
		l, r := "", ""
		if i < len(left) {
			l = left[i]
		}
		if i < len(right) {
			r = right[i]
		}
		lines = append(lines, padRight(l, paneWidth)+separator+padRight(r, rightWidth))
	}
	lines = append(lines, "")
	lines = append(lines, truncateText("Tab switch | Enter open | Backspace up | Space select | U upload | D download | R refresh | Q quit", width))
	if model.message != "" {
		lines = append(lines, truncateText(model.message, width))
	}
	return strings.Join(lines, "\r\n") + "\r\n"
}

func renderFileManagerPane(pane *fileManagerPane, width, pageSize int, active bool) []string {
	titlePrefix := " "
	if active {
		titlePrefix = ">"
	}
	title := fmt.Sprintf("%s %s: %s", titlePrefix, pane.title, pane.cwd)
	lines := []string{truncateText(title, width), strings.Repeat("-", width)}
	if pane.err != nil {
		lines = append(lines, truncateText("! "+pane.err.Error(), width))
	}
	if len(pane.entries) == 0 {
		lines = append(lines, "(empty)")
	}

	start := 0
	if pageSize > 0 {
		start = pane.cursor / pageSize * pageSize
	}
	end := start + pageSize
	if end > len(pane.entries) {
		end = len(pane.entries)
	}
	for idx := start; idx < end; idx++ {
		entry := pane.entries[idx]
		cursor := "  "
		if idx == pane.cursor {
			cursor = "> "
		}
		check := "[ ] "
		if _, ok := pane.selected[entry.Path]; ok {
			check = "[x] "
		}
		name := entry.Name
		if entry.IsDir {
			name += "/"
		}
		lines = append(lines, truncateText(cursor+check+name, width))
	}
	for len(lines) < pageSize+2 {
		lines = append(lines, "")
	}
	lines = append(lines, truncateText(fmt.Sprintf("%d item(s), %d selected", len(pane.entries), len(pane.selected)), width))
	return lines
}

func padRight(text string, width int) string {
	displayWidth := ansi.StringWidth(text)
	if displayWidth >= width {
		return truncateText(text, width)
	}
	return text + strings.Repeat(" ", width-displayWidth)
}

func truncateText(text string, width int) string {
	if width <= 0 {
		return ""
	}
	if ansi.StringWidth(text) <= width {
		return text
	}
	if width <= 1 {
		return ansi.Truncate(text, width, "")
	}
	return ansi.Truncate(text, width, "~")
}

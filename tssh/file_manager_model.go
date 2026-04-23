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
	"sort"
	"strings"
)

type fileManagerPaneID int

const (
	fileManagerLocalPane fileManagerPaneID = iota
	fileManagerRemotePane
)

type fileManagerPane struct {
	title    string
	fs       fileManagerFS
	cwd      string
	entries  []fileManagerEntry
	filtered []fileManagerEntry
	filter   string
	cursor   int
	selected map[string]struct{}
	order    []string
	err      error
}

func newFileManagerPane(title string, fs fileManagerFS, cwd string) *fileManagerPane {
	return &fileManagerPane{
		title:    title,
		fs:       fs,
		cwd:      fs.Clean(cwd),
		selected: make(map[string]struct{}),
	}
}

func (p *fileManagerPane) refresh() error {
	entries, err := p.fs.ReadDir(p.cwd)
	if err != nil {
		p.err = err
		return err
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].IsDir != entries[j].IsDir {
			return entries[i].IsDir
		}
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
	p.entries = entries
	p.applyFilter()
	p.err = nil
	return nil
}

func (p *fileManagerPane) move(delta int) {
	if len(p.filtered) == 0 {
		return
	}
	p.cursor += delta
	if p.cursor < 0 {
		p.cursor = len(p.filtered) - 1
	}
	if p.cursor >= len(p.filtered) {
		p.cursor = 0
	}
	p.err = nil
}

func (p *fileManagerPane) currentEntry() (fileManagerEntry, bool) {
	if p.cursor < 0 || p.cursor >= len(p.filtered) {
		return fileManagerEntry{}, false
	}
	return p.filtered[p.cursor], true
}

func (p *fileManagerPane) enter() error {
	entry, ok := p.currentEntry()
	if !ok || !entry.IsDir {
		return nil
	}
	p.cwd = p.fs.Clean(entry.Path)
	p.cursor = 0
	p.clearSelection()
	p.clearFilter()
	return p.refresh()
}

func (p *fileManagerPane) back() error {
	parent := p.fs.Dir(p.cwd)
	if parent == p.cwd || parent == "." || parent == "" {
		return nil
	}
	p.cwd = p.fs.Clean(parent)
	p.cursor = 0
	p.clearSelection()
	p.clearFilter()
	return p.refresh()
}

func (p *fileManagerPane) toggleCurrent() {
	entry, ok := p.currentEntry()
	if !ok {
		return
	}
	if _, ok := p.selected[entry.Path]; ok {
		delete(p.selected, entry.Path)
		for i, item := range p.order {
			if item == entry.Path {
				p.order = append(p.order[:i], p.order[i+1:]...)
				break
			}
		}
		return
	}
	p.selected[entry.Path] = struct{}{}
	p.order = append(p.order, entry.Path)
}

func (p *fileManagerPane) transferEntries() []fileManagerEntry {
	if len(p.order) == 0 {
		if entry, ok := p.currentEntry(); ok {
			return []fileManagerEntry{entry}
		}
		return nil
	}
	entriesByPath := make(map[string]fileManagerEntry, len(p.filtered))
	for _, entry := range p.filtered {
		entriesByPath[entry.Path] = entry
	}
	result := make([]fileManagerEntry, 0, len(p.order))
	for _, item := range p.order {
		if entry, ok := entriesByPath[item]; ok {
			result = append(result, entry)
		}
	}
	return result
}

func (p *fileManagerPane) clearSelection() {
	p.selected = make(map[string]struct{})
	p.order = nil
}

func (p *fileManagerPane) setFilter(filter string) {
	p.filter = filter
	p.cursor = 0
	p.applyFilter()
}

func (p *fileManagerPane) clearFilter() {
	p.filter = ""
	p.cursor = 0
	p.applyFilter()
}

func (p *fileManagerPane) applyFilter() {
	if p.filter == "" {
		p.filtered = p.entries
	} else {
		p.filtered = make([]fileManagerEntry, 0, len(p.entries))
		for _, entry := range p.entries {
			if fuzzyMatchFileName(entry.Name, p.filter) {
				p.filtered = append(p.filtered, entry)
			}
		}
	}
	if p.cursor >= len(p.filtered) {
		p.cursor = len(p.filtered) - 1
	}
	if p.cursor < 0 {
		p.cursor = 0
	}
}

func fuzzyMatchFileName(name, query string) bool {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return true
	}
	name = strings.ToLower(name)
	idx := 0
	for _, ch := range name {
		if idx >= len(query) {
			return true
		}
		if ch == rune(query[idx]) {
			idx++
		}
	}
	return idx >= len(query)
}

type fileManagerModel struct {
	local     *fileManagerPane
	remote    *fileManagerPane
	active    fileManagerPaneID
	searching bool
	message   string
	cancelled bool
}

func newFileManagerModel(localFS, remoteFS fileManagerFS, localDir, remoteDir string) (*fileManagerModel, error) {
	model := &fileManagerModel{
		local:  newFileManagerPane("Local", localFS, localDir),
		remote: newFileManagerPane("Remote", remoteFS, remoteDir),
		active: fileManagerLocalPane,
	}
	if err := model.local.refresh(); err != nil {
		return nil, fmt.Errorf("read local directory failed: %w", err)
	}
	if err := model.remote.refresh(); err != nil {
		return nil, fmt.Errorf("read remote directory failed: %w", err)
	}
	return model, nil
}

func (m *fileManagerModel) activePane() *fileManagerPane {
	if m.active == fileManagerRemotePane {
		return m.remote
	}
	return m.local
}

func (m *fileManagerModel) switchPane() {
	if m.active == fileManagerLocalPane {
		m.active = fileManagerRemotePane
	} else {
		m.active = fileManagerLocalPane
	}
	m.searching = false
	m.message = ""
}

func (m *fileManagerModel) upload(progress func(fileTransferProgress)) error {
	return m.transfer(m.local, m.remote, progress)
}

func (m *fileManagerModel) download(progress func(fileTransferProgress)) error {
	return m.transfer(m.remote, m.local, progress)
}

func (m *fileManagerModel) transfer(srcPane, dstPane *fileManagerPane, progress func(fileTransferProgress)) error {
	entries := srcPane.transferEntries()
	if len(entries) == 0 {
		return fmt.Errorf("nothing selected")
	}
	for _, entry := range entries {
		target := dstPane.fs.Join(dstPane.cwd, entry.Name)
		if err := copyFileManagerPath(srcPane.fs, dstPane.fs, entry.Path, target, fileTransferOptions{Progress: progress}); err != nil {
			return err
		}
	}
	srcPane.clearSelection()
	if err := dstPane.refresh(); err != nil {
		return err
	}
	m.message = fmt.Sprintf("transferred %d item(s)", len(entries))
	return nil
}

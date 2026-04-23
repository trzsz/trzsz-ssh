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
	"io"
	"os"
)

type fileTransferProgress struct {
	SourcePath string
	TargetPath string
	FileName   string
	Done       int64
	Total      int64
}

type fileTransferOptions struct {
	Progress func(fileTransferProgress)
}

type progressReader struct {
	reader io.Reader
	event  fileTransferProgress
	notify func(fileTransferProgress)
}

func (r *progressReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 && r.notify != nil {
		r.event.Done += int64(n)
		r.notify(r.event)
	}
	return n, err
}

func copyFileManagerPath(srcFS, dstFS fileManagerFS, srcPath, dstPath string, opts fileTransferOptions) error {
	entry, err := srcFS.Stat(srcPath)
	if err != nil {
		return err
	}
	if entry.IsDir {
		return copyFileManagerDir(srcFS, dstFS, entry, dstPath, opts)
	}
	return copyFileManagerFile(srcFS, dstFS, entry, dstPath, opts)
}

func copyFileManagerDir(srcFS, dstFS fileManagerFS, entry fileManagerEntry, dstPath string, opts fileTransferOptions) error {
	mode := entry.Mode.Perm()
	if mode == 0 {
		mode = 0755
	}
	if err := dstFS.MkdirAll(dstPath, mode); err != nil {
		return err
	}

	children, err := srcFS.ReadDir(entry.Path)
	if err != nil {
		return err
	}
	for _, child := range children {
		childDst := dstFS.Join(dstPath, child.Name)
		if child.IsDir {
			if err := copyFileManagerDir(srcFS, dstFS, child, childDst, opts); err != nil {
				return err
			}
			continue
		}
		if err := copyFileManagerFile(srcFS, dstFS, child, childDst, opts); err != nil {
			return err
		}
	}
	return nil
}

func copyFileManagerFile(srcFS, dstFS fileManagerFS, entry fileManagerEntry, dstPath string, opts fileTransferOptions) error {
	if err := dstFS.MkdirAll(dstFS.Dir(dstPath), 0755); err != nil {
		return err
	}

	src, err := srcFS.Open(entry.Path)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := dstFS.Create(dstPath)
	if err != nil {
		return err
	}
	defer dst.Close()

	reader := io.Reader(src)
	if opts.Progress != nil {
		reader = &progressReader{
			reader: src,
			event: fileTransferProgress{
				SourcePath: entry.Path,
				TargetPath: dstPath,
				FileName:   entry.Name,
				Total:      entry.Size,
			},
			notify: opts.Progress,
		}
	}

	if _, err := io.CopyBuffer(dst, reader, make([]byte, 256*1024)); err != nil {
		return err
	}
	if opts.Progress != nil {
		opts.Progress(fileTransferProgress{
			SourcePath: entry.Path,
			TargetPath: dstPath,
			FileName:   entry.Name,
			Done:       entry.Size,
			Total:      entry.Size,
		})
	}
	return nil
}

func formatFileTransferProgress(progress fileTransferProgress) string {
	if progress.Total <= 0 {
		return fmt.Sprintf("transferring %s", progress.FileName)
	}
	percent := progress.Done * 100 / progress.Total
	if percent > 100 {
		percent = 100
	}
	return fmt.Sprintf("transferring %s %d%% (%s/%s)",
		progress.FileName, percent, formatTransferSize(progress.Done), formatTransferSize(progress.Total))
}

func formatTransferSize(size int64) string {
	const unit = int64(1024)
	if size < unit {
		return fmt.Sprintf("%dB", size)
	}
	div, exp := unit, 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(size)/float64(div), "KMGTPE"[exp])
}

func fileManagerPathExists(fs fileManagerFS, name string) bool {
	_, err := fs.Stat(name)
	return err == nil || !os.IsNotExist(err)
}

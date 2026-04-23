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
	"path"
	"path/filepath"
	"time"

	"github.com/pkg/sftp"
)

type fileManagerEntry struct {
	Name    string
	Path    string
	Size    int64
	Mode    os.FileMode
	ModTime time.Time
	IsDir   bool
}

type fileManagerFS interface {
	ReadDir(dir string) ([]fileManagerEntry, error)
	Stat(name string) (fileManagerEntry, error)
	Open(name string) (io.ReadCloser, error)
	Create(name string) (io.WriteCloser, error)
	MkdirAll(name string, perm os.FileMode) error
	Close() error
	Join(elem ...string) string
	Dir(name string) string
	Base(name string) string
	Clean(name string) string
}

type localFileManagerFS struct{}

func (f *localFileManagerFS) ReadDir(dir string) ([]fileManagerEntry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	result := make([]fileManagerEntry, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		result = append(result, fileManagerEntry{
			Name:    entry.Name(),
			Path:    filepath.Join(dir, entry.Name()),
			Size:    info.Size(),
			Mode:    info.Mode(),
			ModTime: info.ModTime(),
			IsDir:   info.IsDir(),
		})
	}
	return result, nil
}

func (f *localFileManagerFS) Stat(name string) (fileManagerEntry, error) {
	info, err := os.Stat(name)
	if err != nil {
		return fileManagerEntry{}, err
	}
	return fileManagerEntry{
		Name:    info.Name(),
		Path:    name,
		Size:    info.Size(),
		Mode:    info.Mode(),
		ModTime: info.ModTime(),
		IsDir:   info.IsDir(),
	}, nil
}

func (f *localFileManagerFS) Open(name string) (io.ReadCloser, error) {
	return os.Open(name)
}

func (f *localFileManagerFS) Create(name string) (io.WriteCloser, error) {
	return os.Create(name)
}

func (f *localFileManagerFS) MkdirAll(name string, perm os.FileMode) error {
	return os.MkdirAll(name, perm)
}

func (f *localFileManagerFS) Close() error {
	return nil
}

func (f *localFileManagerFS) Join(elem ...string) string {
	return filepath.Join(elem...)
}

func (f *localFileManagerFS) Dir(name string) string {
	return filepath.Dir(name)
}

func (f *localFileManagerFS) Base(name string) string {
	return filepath.Base(name)
}

func (f *localFileManagerFS) Clean(name string) string {
	return filepath.Clean(name)
}

type sftpFileManagerFS struct {
	client  *sftp.Client
	session SshSession
}

func newSftpFileManagerFS(client SshClient) (*sftpFileManagerFS, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		_ = session.Close()
		return nil, err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		_ = session.Close()
		return nil, err
	}
	if err := session.RequestSubsystem("sftp"); err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("remote host does not provide sftp subsystem: %w", err)
	}

	sftpClient, err := sftp.NewClientPipe(stdout, stdin)
	if err != nil {
		_ = session.Close()
		return nil, err
	}
	return &sftpFileManagerFS{client: sftpClient, session: session}, nil
}

func (f *sftpFileManagerFS) ReadDir(dir string) ([]fileManagerEntry, error) {
	infos, err := f.client.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	result := make([]fileManagerEntry, 0, len(infos))
	for _, info := range infos {
		result = append(result, fileManagerEntry{
			Name:    info.Name(),
			Path:    path.Join(dir, info.Name()),
			Size:    info.Size(),
			Mode:    info.Mode(),
			ModTime: info.ModTime(),
			IsDir:   info.IsDir(),
		})
	}
	return result, nil
}

func (f *sftpFileManagerFS) Stat(name string) (fileManagerEntry, error) {
	info, err := f.client.Stat(name)
	if err != nil {
		return fileManagerEntry{}, err
	}
	return fileManagerEntry{
		Name:    info.Name(),
		Path:    name,
		Size:    info.Size(),
		Mode:    info.Mode(),
		ModTime: info.ModTime(),
		IsDir:   info.IsDir(),
	}, nil
}

func (f *sftpFileManagerFS) Open(name string) (io.ReadCloser, error) {
	return f.client.Open(name)
}

func (f *sftpFileManagerFS) Create(name string) (io.WriteCloser, error) {
	return f.client.Create(name)
}

func (f *sftpFileManagerFS) MkdirAll(name string, perm os.FileMode) error {
	return f.client.MkdirAll(name)
}

func (f *sftpFileManagerFS) Close() error {
	if f.client != nil {
		_ = f.client.Close()
	}
	if f.session != nil {
		return f.session.Close()
	}
	return nil
}

func (f *sftpFileManagerFS) Join(elem ...string) string {
	return path.Join(elem...)
}

func (f *sftpFileManagerFS) Dir(name string) string {
	return path.Dir(name)
}

func (f *sftpFileManagerFS) Base(name string) string {
	return path.Base(name)
}

func (f *sftpFileManagerFS) Clean(name string) string {
	return path.Clean(name)
}

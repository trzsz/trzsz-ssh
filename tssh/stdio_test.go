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
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWrapStdIOPreservesRedirectedBytes(t *testing.T) {
	payload := []byte("\r\n\n\r\x00\x1a\x1b\x80\xff")
	for i := 0; i < 256; i++ {
		payload = append(payload, byte(i))
	}

	stdin, stdout, stderr := os.Stdin, os.Stdout, os.Stderr
	t.Cleanup(func() { os.Stdin, os.Stdout, os.Stderr = stdin, stdout, stderr })
	files := make([]*os.File, 3)
	for i := range files {
		file, err := os.CreateTemp(t.TempDir(), "stdio")
		require.NoError(t, err)
		t.Cleanup(func() { _ = file.Close() })
		files[i] = file
	}
	_, err := files[0].Write(payload)
	require.NoError(t, err)
	_, err = files[0].Seek(0, io.SeekStart)
	require.NoError(t, err)
	os.Stdin, os.Stdout, os.Stderr = files[0], files[1], files[2]

	serverIn, writer := io.Pipe()
	defer func() { _ = serverIn.Close() }()
	conn := &sshConnection{param: &sshParam{args: &sshArgs{}}}
	wrapStdIO(writer, bytes.NewReader(payload), bytes.NewReader(payload), 0, 0, conn)
	input, err := io.ReadAll(serverIn)
	require.NoError(t, err)
	outputWaitGroup.Wait()
	require.Equal(t, payload, input, "stdin")
	for i, name := range []string{"stdout", "stderr"} {
		_, err := files[i+1].Seek(0, io.SeekStart)
		require.NoError(t, err)
		output, err := io.ReadAll(files[i+1])
		require.NoError(t, err)
		require.Equal(t, payload, output, name)
	}
}

func TestForwardWindowsConsoleNewlines(t *testing.T) {
	terminal := isTerminal
	isTerminal = false
	t.Cleanup(func() { isTerminal = terminal })
	for _, tty := range []bool{false, true} {
		name := "no-pty"
		if tty {
			name = "pty"
		}
		t.Run(name, func(t *testing.T) {
			inputPayload, outputPayload := []byte("line\r\n"), []byte("line\n")
			inputWant, outputWant := inputPayload, outputPayload
			if !tty {
				inputWant = []byte("line\n")
				outputWant = []byte("line\r\n")
			}
			conn := &sshConnection{tty: tty, param: &sshParam{args: &sshArgs{}}}
			reader, writer := io.Pipe()
			defer func() { _ = reader.Close() }()
			go forwardInput(bytes.NewReader(inputPayload), writer, true, 0, 0, conn)
			input, err := io.ReadAll(reader)
			require.NoError(t, err)
			require.Equal(t, inputWant, input)

			file, err := os.CreateTemp(t.TempDir(), "stdout")
			require.NoError(t, err)
			defer func() { _ = file.Close() }()
			forwardOutput(bytes.NewReader(outputPayload), file, true, tty)
			_, err = file.Seek(0, io.SeekStart)
			require.NoError(t, err)
			output, err := io.ReadAll(file)
			require.NoError(t, err)
			require.Equal(t, outputWant, output)
		})
	}
}

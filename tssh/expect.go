/*
MIT License

Copyright (c) 2023 Lonny Wong <lonnywong@qq.com>
Copyright (c) 2023 [Contributors](https://github.com/trzsz/trzsz-ssh/graphs/contributors)

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
	"context"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const kDefaultExpectTimeout = 30

func decodeExpectText(text string) string {
	var buf strings.Builder
	state := byte(0)
	for _, c := range text {
		if state == 0 {
			if c == '\\' {
				state = '\\'
				continue
			}
			buf.WriteRune(c)
			continue
		}
		state = 0
		switch c {
		case '\\':
			buf.WriteRune('\\')
		case 'r':
			buf.WriteRune('\r')
		default:
			warning("token [\\%c] in [%s] is not supported yet", c, text)
			buf.WriteRune('\\')
			buf.WriteRune(c)
		}
	}
	if state != 0 {
		warning("[%s] ends with \\ is invalid", text)
		buf.WriteRune('\\')
	}
	return buf.String()
}

type sshExpect struct {
	outputChan    chan []byte
	outputBuffer  strings.Builder
	expectContext context.Context
}

func (e *sshExpect) wrapOutput(reader io.Reader, writer io.Writer) {
	for {
		buffer := make([]byte, 32*1024)
		n, err := reader.Read(buffer)
		if n > 0 {
			buf := buffer[:n]
			if e.expectContext.Err() != nil {
				if err := writeAll(writer, buf); err != nil {
					warning("expect wrap output write failed: %v", err)
				}
				break
			}
			e.outputChan <- buf
		}
		if err == io.EOF {
			return
		}
		if err != nil {
			warning("expect wrap output read failed: %v", err)
			return
		}
	}
	if _, err := io.Copy(writer, reader); err != nil && err != io.EOF {
		warning("expect wrap output failed: %v", err)
	}
}

func (e *sshExpect) waitForPattern(pattern string) error {
	expr := strings.ReplaceAll(pattern, "*", ".*")
	re, err := regexp.Compile(expr)
	if err != nil {
		warning("compile expect expr [%s] failed: %v", expr, err)
		return err
	}
	e.outputBuffer.Reset()
	for {
		select {
		case <-e.expectContext.Done():
			warning("expect timeout")
			return e.expectContext.Err()
		case buf := <-e.outputChan:
			output := string(buf)
			debug("expect output: %s", strconv.QuoteToASCII(output))
			e.outputBuffer.WriteString(output)
		}
		if re.MatchString(e.outputBuffer.String()) {
			debug("expect match: %s", pattern)
			return nil
		}
	}
}

func (e *sshExpect) execInteractions(args *sshArgs, writer io.Writer, expectCount uint32) {
	for i := uint32(1); i <= expectCount; i++ {
		pattern := getExOptionConfig(args, fmt.Sprintf("ExpectPattern%d", i))
		debug("expect pattern %d: %s", i, pattern)
		if pattern != "" {
			if err := e.waitForPattern(pattern); err != nil {
				return
			}
		}
		if e.expectContext.Err() != nil {
			return
		}
		var input string
		pass := getExOptionConfig(args, fmt.Sprintf("ExpectSendPass%d", i))
		if pass != "" {
			secret, err := decodeSecret(pass)
			if err != nil {
				warning("decode secret [%s] failed: %v", pass, err)
				return
			}
			debug("expect send %d: %s", i, strings.Repeat("*", len(secret)))
			input = secret + "\r"
		} else {
			text := getExOptionConfig(args, fmt.Sprintf("ExpectSendText%d", i))
			if text == "" {
				continue
			}
			debug("expect send %d: %s", i, text)
			input = decodeExpectText(text)
		}
		if err := writeAll(writer, []byte(input)); err != nil {
			warning("expect send input failed: %v", err)
			return
		}
	}
}

func getExpectCount(args *sshArgs) uint32 {
	expectCount := getExOptionConfig(args, "ExpectCount")
	if expectCount == "" {
		return 0
	}
	count, err := strconv.ParseUint(expectCount, 10, 32)
	if err != nil {
		warning("Invalid ExpectCount [%s]: %v", expectCount, err)
		return 0
	}
	return uint32(count)
}

func getExpectTimeout(args *sshArgs) uint32 {
	expectCount := getExOptionConfig(args, "ExpectTimeout")
	if expectCount == "" {
		return kDefaultExpectTimeout
	}
	count, err := strconv.ParseUint(expectCount, 10, 32)
	if err != nil {
		warning("Invalid ExpectTimeout [%s]: %v", expectCount, err)
		return kDefaultExpectTimeout
	}
	return uint32(count)
}

func execExpectInteractions(args *sshArgs, serverIn io.Writer,
	serverOut io.Reader, serverErr io.Reader) (io.Reader, io.Reader) {
	expectCount := getExpectCount(args)
	if expectCount <= 0 {
		return serverOut, serverErr
	}

	outReader, outWriter := io.Pipe()
	errReader, errWriter := io.Pipe()

	var ctx context.Context
	var cancel context.CancelFunc
	if expectTimeout := getExpectTimeout(args); expectTimeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), time.Duration(expectTimeout)*time.Second)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()

	expect := &sshExpect{outputChan: make(chan []byte, 1), expectContext: ctx}
	go expect.wrapOutput(serverOut, outWriter)
	go expect.wrapOutput(serverErr, errWriter)

	expect.execInteractions(args, serverIn, expectCount)

	return outReader, errReader
}

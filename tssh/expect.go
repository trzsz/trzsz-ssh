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
	"unicode"
)

const kDefaultExpectTimeout = 30

func decodeExpectText(text string) string {
	var buf strings.Builder
	state := byte(0)
	for _, c := range text {
		if state == 0 {
			switch c {
			case '\\':
				state = '\\'
			default:
				buf.WriteRune(c)
			}
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

func quoteExpectPattern(pattern string) string {
	var buf strings.Builder
	for _, c := range pattern {
		switch c {
		case '*':
			buf.WriteString(".*")
		case '?', '(', ')', '[', ']', '{', '}', '.', '+', ',', '-', '^', '$', '|', '\\':
			buf.WriteRune('\\')
			buf.WriteRune(c)
		default:
			buf.WriteRune(c)
		}
	}
	return buf.String()
}

type caseSend struct {
	pattern string
	display string
	input   []byte
	re      *regexp.Regexp
	buffer  strings.Builder
}

type caseSendList struct {
	writer io.Writer
	list   []*caseSend
}

func (c *caseSendList) splitConfig(config string) (string, string, error) {
	index := strings.IndexFunc(config, unicode.IsSpace)
	if index <= 0 {
		return "", "", fmt.Errorf("invalid expect case send: %s", config)
	}
	pattern := strings.TrimSpace(config[:index])
	send := strings.TrimSpace(config[index+1:])
	if pattern == "" || send == "" {
		return "", "", fmt.Errorf("invalid expect case send: %s", config)
	}
	return pattern, send, nil
}

func (c *caseSendList) addCase(re *regexp.Regexp, pattern, display, input string) {
	c.list = append(c.list, &caseSend{
		pattern: pattern,
		display: display,
		input:   []byte(input),
		re:      re,
	})
}

func (c *caseSendList) addCaseSendPass(config string) error {
	pattern, secret, err := c.splitConfig(config)
	if err != nil {
		return err
	}
	expr := quoteExpectPattern(pattern)
	re, err := regexp.Compile(expr)
	if err != nil {
		return fmt.Errorf("compile expect expr [%s] failed: %v", expr, err)
	}
	pass, err := decodeSecret(secret)
	if err != nil {
		return fmt.Errorf("decode secret [%s] failed: %v", secret, err)
	}
	c.addCase(re, pattern, strings.Repeat("*", len(pass))+"\\r", pass+"\r")
	return nil
}

func (c *caseSendList) addCaseSendText(config string) error {
	pattern, text, err := c.splitConfig(config)
	if err != nil {
		return err
	}
	expr := quoteExpectPattern(pattern)
	re, err := regexp.Compile(expr)
	if err != nil {
		return fmt.Errorf("compile expect expr [%s] failed: %v", expr, err)
	}
	c.addCase(re, pattern, text, decodeExpectText(text))
	return nil
}

func (c *caseSendList) handleOutput(output string) {
	for _, cs := range c.list {
		cs.buffer.WriteString(output)
		if cs.re.MatchString(cs.buffer.String()) {
			debug("expect case match: %s", cs.pattern)
			debug("expect case send: %s", cs.display)
			if err := writeAll(c.writer, cs.input); err != nil {
				warning("expect send input failed: %v", err)
			}
			cs.buffer.Reset()
		} else {
			debug("expect case not match: %s", cs.pattern)
		}
	}
}

type sshExpect struct {
	pre string
	ctx context.Context
	out chan []byte
	err chan []byte
}

func (e *sshExpect) captureOutput(reader io.Reader, ch chan<- []byte) ([]byte, error) {
	defer close(ch)
	for e.ctx.Err() == nil {
		buffer := make([]byte, 32*1024)
		n, err := reader.Read(buffer)
		if n > 0 {
			buf := buffer[:n]
			select {
			case <-e.ctx.Done():
				return buf, nil
			case ch <- buf:
				debug("expect capture output: %s", strconv.QuoteToASCII(string(buf)))
			}
		}
		if err == io.EOF {
			return nil, err
		}
		if err != nil {
			if e.ctx.Err() == nil {
				warning("expect read output failed: %v", err)
			}
			return nil, err
		}
	}
	return nil, nil
}

func (e *sshExpect) wrapOutput(reader io.Reader, writer io.Writer, ch chan []byte) {
	buf, err := e.captureOutput(reader, ch)
	if err != nil {
		return
	}
	if writer == nil {
		return
	}
	for data := range ch {
		if err := writeAll(writer, data); err != nil {
			warning("expect write output failed: %v", err)
			return
		}
	}
	if buf != nil {
		if err := writeAll(writer, buf); err != nil {
			warning("expect write output failed: %v", err)
			return
		}
	}
	if _, err := io.Copy(writer, reader); err != nil && err != io.EOF {
		warning("expect copy output failed: %v", err)
	}
}

func (e *sshExpect) waitForPattern(pattern string, caseSends *caseSendList) error {
	expr := quoteExpectPattern(pattern)
	re, err := regexp.Compile(expr)
	if err != nil {
		warning("compile expect expr [%s] failed: %v", expr, err)
		return err
	}
	var builder strings.Builder
	for {
		var buf []byte
		select {
		case <-e.ctx.Done():
			return e.ctx.Err()
		case buf = <-e.out:
		case buf = <-e.err:
		}
		if len(buf) == 0 {
			continue
		}
		output := strconv.QuoteToASCII(string(buf))
		caseSends.handleOutput(output[1 : len(output)-1])
		builder.WriteString(output[1 : len(output)-1])
		if pattern != "" && re.MatchString(builder.String()) {
			debug("expect match: %s", pattern)
			// cleanup for next expect
			for {
				select {
				case <-e.out:
				case <-e.err:
				default:
					return nil
				}
			}
		} else {
			debug("expect not match: %s", pattern)
		}
	}
}

func (e *sshExpect) getExpectSendInput(alias string, idx uint32) (string, string) {
	if pass := getExConfig(alias, fmt.Sprintf("%sExpectSendPass%d", e.pre, idx)); pass != "" {
		secret, err := decodeSecret(pass)
		if err != nil {
			warning("decode %sExpectSendPass%d [%s] failed: %v", e.pre, idx, pass, err)
			return "", ""
		}
		return secret, ""
	}

	if text := getExConfig(alias, fmt.Sprintf("%sExpectSendText%d", e.pre, idx)); text != "" {
		return decodeExpectText(text), text
	}

	if encOtp := getExConfig(alias, fmt.Sprintf("%sExpectSendEncOtp%d", e.pre, idx)); encOtp != "" {
		command, err := decodeSecret(encOtp)
		if err != nil {
			warning("decode %sExpectSendEncOtp%d [%s] failed: %v", e.pre, idx, encOtp, err)
			return "", ""
		}
		return getOtpCommandOutput(command), ""
	}

	if command := getExConfig(alias, fmt.Sprintf("%sExpectSendOtp%d", e.pre, idx)); command != "" {
		return getOtpCommandOutput(command), ""
	}

	return "", ""
}

func (e *sshExpect) execInteractions(alias string, writer io.Writer, expectCount uint32) {
	for idx := uint32(1); idx <= expectCount; idx++ {
		pattern := getExConfig(alias, fmt.Sprintf("%sExpectPattern%d", e.pre, idx))
		if pattern != "" {
			debug("expect %d pattern: %s", idx, pattern)
		} else {
			warning("expect %d pattern is empty, no output will be matched", idx)
		}
		caseSends := &caseSendList{writer: writer}
		for _, cfg := range getAllExConfig(alias, fmt.Sprintf("%sExpectCaseSendPass%d", e.pre, idx)) {
			if err := caseSends.addCaseSendPass(cfg); err != nil {
				warning("Invalid ExpectCaseSendPass%d: %v", idx, err)
			}
		}
		for _, cfg := range getAllExConfig(alias, fmt.Sprintf("%sExpectCaseSendText%d", e.pre, idx)) {
			if err := caseSends.addCaseSendText(cfg); err != nil {
				warning("Invalid ExpectCaseSendText%d: %v", idx, err)
			}
		}
		if err := e.waitForPattern(pattern, caseSends); err != nil {
			return
		}
		if e.ctx.Err() != nil {
			return
		}
		input, text := e.getExpectSendInput(alias, idx)
		if input == "" {
			warning("expect %d send nothing", idx)
			continue
		}
		if text != "" {
			debug("expect %d send: %s", idx, text)
		} else {
			debug("expect %d send: %s\\r", idx, strings.Repeat("*", len(input)))
			input += "\r"
		}
		if err := writeAll(writer, []byte(input)); err != nil {
			warning("expect %d send input failed: %v", idx, err)
			return
		}
	}
}

func getExpectCount(args *sshArgs, prefix string) uint32 {
	expectCount := getExOptionConfig(args, prefix+"ExpectCount")
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

func getExpectTimeout(args *sshArgs, prefix string) uint32 {
	expectCount := getExOptionConfig(args, prefix+"ExpectTimeout")
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
	expectCount := getExpectCount(args, "")
	if expectCount <= 0 {
		return serverOut, serverErr
	}

	outReader, outWriter := io.Pipe()
	errReader, errWriter := io.Pipe()

	var ctx context.Context
	var cancel context.CancelFunc
	expectTimeout := getExpectTimeout(args, "")
	if expectTimeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), time.Duration(expectTimeout)*time.Second)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()

	expect := &sshExpect{
		ctx: ctx,
		out: make(chan []byte, 10),
		err: make(chan []byte, 10),
	}
	go expect.wrapOutput(serverOut, outWriter, expect.out)
	go expect.wrapOutput(serverErr, errWriter, expect.err)

	expect.execInteractions(args.Destination, serverIn, expectCount)

	if ctx.Err() == context.DeadlineExceeded {
		warning("expect timeout after %d seconds", expectTimeout)
		_, _ = serverIn.Write([]byte("\r")) // enter for shell prompt if timeout
	}

	return outReader, errReader
}

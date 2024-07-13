/*
MIT License

Copyright (c) 2023-2024 The Trzsz SSH Authors.

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

const (
	kDefaultExpectTimeout = 30
	kDefaultExpectSleepMS = 100
)

type sshExpect struct {
	param *sshParam
	args  *sshArgs
	pre   string
	ctx   context.Context
	out   chan []byte
	err   chan []byte
}

type expectSender struct {
	expect *sshExpect
	passwd bool
	input  string
}

type expectSendText struct {
	showText string
	sendText string
}

type caseSend struct {
	pattern string
	sender  *expectSender
	re      *regexp.Regexp
	buffer  strings.Builder
}

type caseSendList struct {
	expect *sshExpect
	writer io.Writer
	list   []*caseSend
}

func newPassSender(expect *sshExpect, input string) *expectSender {
	if input == "" {
		return nil
	}
	return &expectSender{expect, true, input}
}

func newTextSender(expect *sshExpect, input string) *expectSender {
	if input == "" {
		return nil
	}
	return &expectSender{expect, false, input}
}

func (s *expectSender) newSendText(showText, sendText string) *expectSendText {
	var err error
	showText, err = expandTokens(showText, s.expect.args, s.expect.param, "%hprnLlj")
	if err != nil {
		warning("expand send text [%s] failed: %v", showText, err)
	} else {
		sendText, err = expandTokens(sendText, s.expect.args, s.expect.param, "%hprnLlj")
		if err != nil {
			warning("expand send text %s failed: %v", strconv.QuoteToASCII(sendText), strconv.QuoteToASCII(err.Error()))
		}
	}
	return &expectSendText{showText: showText, sendText: sendText}
}

func (s *expectSender) decodeText(text string) []*expectSendText {
	var texts []*expectSendText
	var buf strings.Builder
	state := byte(0)
	idx := 0
	for i, c := range text {
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
		case 'n':
			buf.WriteRune('\n')
		case '|':
			texts = append(texts, s.newSendText(text[idx:i-1], buf.String()))
			idx = i + 1
			buf.Reset()
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
	texts = append(texts, s.newSendText(text[idx:], buf.String()))
	return texts
}

func (s *expectSender) getExpectPsssSleep() (bool, bool) {
	passSleep := getExConfig(s.expect.args.Destination, fmt.Sprintf("%sExpectPassSleep", s.expect.pre))
	switch strings.ToLower(passSleep) {
	case "each":
		return true, false
	case "enter":
		return false, true
	default:
		return false, false
	}
}

func (s *expectSender) getExpectSleepTime() time.Duration {
	expectSleepMS := getExConfig(s.expect.args.Destination, fmt.Sprintf("%sExpectSleepMS", s.expect.pre))
	if expectSleepMS == "" {
		return kDefaultExpectSleepMS * time.Millisecond
	}
	sleepMS, err := strconv.ParseUint(expectSleepMS, 10, 32)
	if err != nil {
		warning("Invalid %sExpectSleepMS [%s]: %v", s.expect.pre, expectSleepMS, err)
		return kDefaultExpectSleepMS * time.Millisecond
	}
	return time.Duration(sleepMS) * time.Millisecond
}

func (s *expectSender) sendInput(writer io.Writer, id string) bool {
	if s == nil {
		warning("expect %s send nothing", id)
		return true
	}
	var sleepTime time.Duration
	if s.passwd {
		eachSleep, enterSleep := s.getExpectPsssSleep()
		if eachSleep || enterSleep {
			sleepTime = s.getExpectSleepTime()
		}
		for _, input := range []byte(s.input) {
			debug("expect %s send: %s", id, "*")
			if err := writeAll(writer, []byte{input}); err != nil {
				warning("expect %s send input failed: %v", id, err)
				return false
			}
			if eachSleep {
				debug("expect %s sleep: %v", id, sleepTime)
				time.Sleep(sleepTime)
			}
		}
		if enterSleep {
			debug("expect %s sleep: %v", id, sleepTime)
			time.Sleep(sleepTime)
		}
		debug("expect %s send: \\r", id)
		if err := writeAll(writer, []byte("\r")); err != nil {
			warning("expect %s send input failed: %v", id, err)
			return false
		}
		return true
	}
	for i, text := range s.decodeText(s.input) {
		if i > 0 {
			if i == 1 {
				sleepTime = s.getExpectSleepTime()
			}
			debug("expect %s sleep: %v", id, sleepTime)
			time.Sleep(sleepTime)
		}
		if text.sendText == "" {
			continue
		}
		debug("expect %s send: %s", id, text.showText)
		if err := writeAll(writer, []byte(text.sendText)); err != nil {
			warning("expect %s send input failed: %v", id, err)
			return false
		}
	}
	return true
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

func (c *caseSendList) addCase(re *regexp.Regexp, pattern string, sender *expectSender) {
	c.list = append(c.list, &caseSend{
		pattern: pattern,
		sender:  sender,
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
	c.addCase(re, pattern, newPassSender(c.expect, pass))
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
	c.addCase(re, pattern, newTextSender(c.expect, text))
	return nil
}

func (c *caseSendList) handleOutput(output string) {
	for _, cs := range c.list {
		cs.buffer.WriteString(output)
		if cs.re.MatchString(cs.buffer.String()) {
			debug("expect case match: %s", cs.pattern)
			cs.sender.sendInput(c.writer, "case")
			cs.buffer.Reset()
		} else {
			debug("expect case not match: %s", cs.pattern)
		}
	}
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
	if reader == nil {
		return
	}
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

func (e *sshExpect) getExpectSender(idx int) *expectSender {
	if pass := getExConfig(e.args.Destination, fmt.Sprintf("%sExpectSendPass%d", e.pre, idx)); pass != "" {
		secret, err := decodeSecret(pass)
		if err != nil {
			warning("decode %sExpectSendPass%d [%s] failed: %v", e.pre, idx, pass, err)
			return nil
		}
		return newPassSender(e, secret)
	}

	if text := getExConfig(e.args.Destination, fmt.Sprintf("%sExpectSendText%d", e.pre, idx)); text != "" {
		return newTextSender(e, text)
	}

	if encTotp := getExConfig(e.args.Destination, fmt.Sprintf("%sExpectSendEncTotp%d", e.pre, idx)); encTotp != "" {
		secret, err := decodeSecret(encTotp)
		if err != nil {
			warning("decode %sExpectSendEncTotp%d [%s] failed: %v", e.pre, idx, encTotp, err)
			return nil
		}
		return newPassSender(e, getTotpCode(secret))
	}

	if encOtp := getExConfig(e.args.Destination, fmt.Sprintf("%sExpectSendEncOtp%d", e.pre, idx)); encOtp != "" {
		command, err := decodeSecret(encOtp)
		if err != nil {
			warning("decode %sExpectSendEncOtp%d [%s] failed: %v", e.pre, idx, encOtp, err)
			return nil
		}
		return newPassSender(e, getOtpCommandOutput(command))
	}

	if secret := getExConfig(e.args.Destination, fmt.Sprintf("%sExpectSendTotp%d", e.pre, idx)); secret != "" {
		return newPassSender(e, getTotpCode(secret))
	}

	if command := getExConfig(e.args.Destination, fmt.Sprintf("%sExpectSendOtp%d", e.pre, idx)); command != "" {
		return newPassSender(e, getOtpCommandOutput(command))
	}

	return nil
}

func (e *sshExpect) execInteractions(writer io.Writer, expectCount int) {
	for idx := 1; idx <= expectCount; idx++ {
		pattern := getExConfig(e.args.Destination, fmt.Sprintf("%sExpectPattern%d", e.pre, idx))
		if pattern != "" {
			debug("expect %d pattern: %s", idx, pattern)
		} else {
			warning("expect %d pattern is empty, no output will be matched", idx)
		}
		caseSends := &caseSendList{e, writer, nil}
		for _, cfg := range getAllExConfig(e.args.Destination, fmt.Sprintf("%sExpectCaseSendPass%d", e.pre, idx)) {
			if err := caseSends.addCaseSendPass(cfg); err != nil {
				warning("Invalid ExpectCaseSendPass%d: %v", idx, err)
			}
		}
		for _, cfg := range getAllExConfig(e.args.Destination, fmt.Sprintf("%sExpectCaseSendText%d", e.pre, idx)) {
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
		sender := e.getExpectSender(idx)
		if !sender.sendInput(writer, strconv.Itoa(idx)) {
			return
		}
	}
}

func getExpectCount(args *sshArgs, prefix string) int {
	expectCount := getExOptionConfig(args, prefix+"ExpectCount")
	if expectCount == "" {
		return 0
	}
	count, err := strconv.ParseUint(expectCount, 10, 32)
	if err != nil {
		warning("Invalid ExpectCount [%s]: %v", expectCount, err)
		return 0
	}
	return int(count)
}

func getExpectTimeout(args *sshArgs, prefix string) int {
	expectCount := getExOptionConfig(args, prefix+"ExpectTimeout")
	if expectCount == "" {
		return kDefaultExpectTimeout
	}
	count, err := strconv.ParseUint(expectCount, 10, 32)
	if err != nil {
		warning("Invalid ExpectTimeout [%s]: %v", expectCount, err)
		return kDefaultExpectTimeout
	}
	return int(count)
}

func execExpectInteractions(args *sshArgs, ss *sshClientSession) {
	expectCount := getExpectCount(args, "")
	if expectCount <= 0 {
		return
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
		param: ss.param,
		args:  args,
		ctx:   ctx,
		out:   make(chan []byte, 10),
		err:   make(chan []byte, 10),
	}
	go expect.wrapOutput(ss.serverOut, outWriter, expect.out)
	go expect.wrapOutput(ss.serverErr, errWriter, expect.err)

	expect.execInteractions(ss.serverIn, expectCount)

	if ctx.Err() == context.DeadlineExceeded {
		warning("expect timeout after %d seconds", expectTimeout)
		_, _ = ss.serverIn.Write([]byte("\r")) // enter for shell prompt if timeout
	}

	ss.serverOut = outReader
	ss.serverErr = errReader
}

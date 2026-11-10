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
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trzsz/ssh_config"
)

func TestExpectRegexConfigValue(t *testing.T) {
	config, err := ssh_config.Decode(strings.NewReader(`
Host bastion
    #!! ExpectRegex1 Shell\]\$
    #!! ExpectRegex2 (\d{3}):.*192\.0\.2\.10
    #!! ExpectRegex3 (\d{3}):[^\x1b\r\n]*192\.0\.2\.10[^\x1b\r\n]*ssh\s+root
`))
	require.NoError(t, err)

	value, err := config.Get("bastion", "ExpectRegex1")
	require.NoError(t, err)
	assert.Equal(t, `Shell\]\$`, value)

	value, err = config.Get("bastion", "ExpectRegex2")
	require.NoError(t, err)
	assert.Equal(t, `(\d{3}):.*192\.0\.2\.10`, value)

	value, err = config.Get("bastion", "ExpectRegex3")
	require.NoError(t, err)
	assert.Equal(t, `(\d{3}):[^\x1b\r\n]*192\.0\.2\.10[^\x1b\r\n]*ssh\s+root`, value)
}

func TestExpectCaptureGlobalNumbering(t *testing.T) {
	assert := assert.New(t)

	e := &sshExpect{}
	e.saveCaptures(regexp.MustCompile(`(\d+)-(\d+)`), "10-20")
	e.saveCaptures(regexp.MustCompile(`(\w+)`), "abc")

	assert.Equal(map[string]string{"1": "10", "2": "20", "3": "abc"}, e.captures)
}

func TestExpectCaptureNamedGlobal(t *testing.T) {
	assert := assert.New(t)

	originalEnableWarning := enableWarningLogging
	enableWarningLogging = false
	defer func() { enableWarningLogging = originalEnableWarning }()

	e := &sshExpect{}
	e.saveCaptures(regexp.MustCompile(`(?P<id>\d{3})`), "006")
	e.saveCaptures(regexp.MustCompile(`(?P<id>\d{3})`), "007")

	assert.Equal("007", e.captures["id"])
	assert.Equal("006", e.captures["1"])
	assert.Equal("007", e.captures["2"])
}

func TestExpectCaptureNumericNameKeepsExisting(t *testing.T) {
	assert := assert.New(t)

	originalEnableWarning := enableWarningLogging
	enableWarningLogging = false
	defer func() { enableWarningLogging = originalEnableWarning }()

	e := &sshExpect{}
	e.saveCaptures(regexp.MustCompile(`(?P<1>\d{3})`), "006")
	e.saveCaptures(regexp.MustCompile(`(?P<1>\d{3})`), "007")

	assert.Equal("006", e.captures["1"])
	assert.Equal("007", e.captures["2"])
}

func TestExpectCaptureBraceAndNumberEquivalence(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	e := &sshExpect{
		param:    &sshParam{args: &sshArgs{}},
		captures: map[string]string{"1": "006"},
	}
	sender := newTextSender(e, "dummy")
	require.NotNil(sender)

	texts := sender.decodeText("%1 %{1}\r")
	require.Len(texts, 1)
	assert.Equal("006 006\r", texts[0].sendText)
}

func TestExpectCaptureIndexAboveNine(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	e := &sshExpect{}
	e.saveCaptures(regexp.MustCompile(`(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)`), "abcdefghij")
	assert.Equal("j", e.captures["10"])

	sender := newTextSender(&sshExpect{
		param:    &sshParam{args: &sshArgs{}},
		captures: e.captures,
	}, "dummy")
	require.NotNil(sender)

	texts := sender.decodeText("%{10}\r")
	require.Len(texts, 1)
	assert.Equal("j\r", texts[0].sendText)
}

func TestExpectRegexTokenEscaping(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	param := &sshParam{
		args: &sshArgs{Destination: "192.0.2.10"},
		host: "192.0.2.10",
	}

	expanded, err := expandTokensForRegex(`(\d{3}):.*%n`, param, "%hprnLlj")
	require.NoError(err)
	assert.Equal(`(\d{3}):.*192\.0\.2\.10`, expanded)

	re := regexp.MustCompile(expanded)
	assert.True(re.MatchString("006: 192.0.2.10"))
	assert.False(re.MatchString("006: 192x0x2x10"))

	raw, err := expandTokens(`(\d{3}):.*%n`, param, "%hprnLlj")
	require.NoError(err)
	assert.Equal(`(\d{3}):.*192.0.2.10`, raw)
}

func TestExpectSendTextDoesNotEscapeTokens(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	e := &sshExpect{
		param: &sshParam{
			args: &sshArgs{Destination: "192.0.2.10"},
			host: "192.0.2.10",
		},
	}
	sender := newTextSender(e, "dummy")
	require.NotNil(sender)

	texts := sender.decodeText("ls %n\r")
	require.Len(texts, 1)
	assert.Equal("ls 192.0.2.10\r", texts[0].sendText)
}

func TestExpectWaitForPatternRawRegexCapture(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	e := &sshExpect{
		ctx: context.Background(),
		out: make(chan []byte, 10),
		err: make(chan []byte, 10),
	}
	e.out <- []byte("ls 192.0.2.10\r\n")
	e.out <- []byte("006: 192.0.2.10\r\nOpt> ")

	_, err := e.waitForPattern("", `(\d{3}):.*192\.0\.2\.10`, &caseSendList{})
	require.NoError(err)
	assert.Equal("006", e.captures["1"])
}

func TestExpectRegexCaptureTUILine(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	e := &sshExpect{
		ctx: context.Background(),
		out: make(chan []byte, 10),
		err: make(chan []byte, 10),
	}
	e.out <- []byte("\x1b[H\x1b[J\x1b[1024D\x1b[K  [BastionShell]\x1b[1B\x1b[1024D\x1b[K  " +
		"005: server-a / server-b   192.0.2.10:22    ssh   [EMPTY]   physical  \x1b[1B" +
		"\x1b[1024D\x1b[K  006: server-a / server-b   192.0.2.10:22    ssh   root      physical  \x1b[1B")

	_, err := e.waitForPattern("", `(\d{3}):[^\x1b\r\n]*192\.0\.2\.10[^\x1b\r\n]*ssh\s+root`, &caseSendList{})
	require.NoError(err)
	assert.Equal("006", e.captures["1"])
}

func TestExpectWaitForPatternShellPrompt(t *testing.T) {
	require := require.New(t)

	e := &sshExpect{
		ctx: context.Background(),
		out: make(chan []byte, 10),
		err: make(chan []byte, 10),
	}
	e.out <- []byte("\x1b]0;BastionShell\a\x1b[H\x1b[J==>Loading instances, please wait ...\r\n" +
		"Type 'help' to learn how to use the bastion prompt.\r\n[BastionShell]$ \r\n[BastionShell]$ ")

	_, err := e.waitForPattern("", `Shell\]\$`, &caseSendList{})
	require.NoError(err)
}

func TestExpectSaveCapturesNamedAndNumeric(t *testing.T) {
	assert := assert.New(t)

	e := &sshExpect{}
	e.saveCaptures(regexp.MustCompile(`(?P<id>\d{3}):`), "006:")
	assert.Equal("006", e.captures["id"])
	assert.Equal("006", e.captures["1"])
}

func TestExpectSaveCapturesPersistence(t *testing.T) {
	assert := assert.New(t)

	e := &sshExpect{captures: map[string]string{"1": "006"}}
	e.saveCaptures(regexp.MustCompile(`Shell\]\$`), "Shell]$")
	assert.Equal("006", e.captures["1"])
}

func TestExpectSendTextExpansion(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	e := &sshExpect{
		param:    &sshParam{args: &sshArgs{}},
		captures: map[string]string{"id": "006", "1": "006"},
	}
	sender := newTextSender(e, "dummy")
	require.NotNil(sender)

	texts := sender.decodeText("open %{id} %1\r")
	require.Len(texts, 1)
	assert.Equal("open 006 006\r", texts[0].sendText)
}

func TestExpectWildcardBackwardCompatibility(t *testing.T) {
	require := require.New(t)

	e := &sshExpect{
		ctx: context.Background(),
		out: make(chan []byte, 10),
		err: make(chan []byte, 10),
	}
	e.out <- []byte("password: ")

	_, err := e.waitForPattern("*assword", "", &caseSendList{})
	require.NoError(err)
}

func TestExpandTokensWithoutCaptures(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	param := &sshParam{args: &sshArgs{}}

	_, err := expandTokens("%1", param, "%hprnLlj")
	require.Error(err)
	assert.Contains(err.Error(), "token [%1]")

	_, err = expandTokens("%{id}", param, "%hprnLlj")
	require.Error(err)
	assert.Contains(err.Error(), "token [%{]")

	result, err := expandTokens("%%", param, "%hprnLlj")
	require.NoError(err)
	assert.Equal("%", result)
}

type expectTestWriter func([]byte) (int, error)

func (w expectTestWriter) Write(p []byte) (int, error) {
	return w(p)
}

func TestExpectInteractionsRegexCapture(t *testing.T) {
	require := require.New(t)

	originalUserConfig, originalEnableWarning := userConfig, enableWarningLogging
	defer func() { userConfig, enableWarningLogging = originalUserConfig, originalEnableWarning }()
	userConfig, enableWarningLogging = &tsshConfig{}, false

	args := &sshArgs{
		Destination: "192.0.2.10",
		Option: sshOption{options: map[string][]string{
			"expectregex1":    {`(Opt)>`},
			"expectsendtext1": {`ls %n\r`},
			"expectregex2":    {`(\d{3}):.*%n`},
			"expectsendtext2": {`q\r`},
			"expectregex3":    {`Shell\]\$`},
			"expectsendtext3": {`open %2\r`},
		}},
	}
	e := &sshExpect{
		param: &sshParam{args: args},
		ctx:   context.Background(),
		out:   make(chan []byte, 10),
		err:   make(chan []byte, 10),
	}

	sent := make(chan string, 3)
	writer := expectTestWriter(func(p []byte) (int, error) {
		sent <- string(p)
		return len(p), nil
	})
	done := make(chan struct{})
	go func() {
		e.execInteractions(writer, 3)
		close(done)
	}()

	recvSent := func() string {
		t.Helper()
		select {
		case s := <-sent:
			return s
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for expect send")
			return ""
		}
	}

	e.out <- []byte("Opt> ")
	require.Equal("ls 192.0.2.10\r", recvSent())
	e.out <- []byte("ls 192.0.2.10\r\n006: 192.0.2.10\r\nOpt> ")
	require.Equal("q\r", recvSent())
	e.out <- []byte("Shell]$ ")
	require.Equal("open 006\r", recvSent())

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("execInteractions did not finish")
	}
}

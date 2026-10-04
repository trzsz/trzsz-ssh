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
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestMuxMessageRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, muxWriteMessage(&buf, kMuxSFailure, uint32(42), "no way"))

	// uint32 length | uint32 type | uint32 rid | string reason
	assert.Equal(t, uint32(4+4+4+6), binary.BigEndian.Uint32(buf.Bytes()[:4]))

	msgType, body, err := muxReadMessage(&buf)
	require.NoError(t, err)
	assert.Equal(t, kMuxSFailure, msgType)
	rid, ok := muxReadUint32(&body)
	require.True(t, ok)
	assert.Equal(t, uint32(42), rid)
	reason, ok := muxReadString(&body)
	require.True(t, ok)
	assert.Equal(t, "no way", reason)
	_, ok = muxReadUint32(&body)
	assert.False(t, ok)
}

func TestMuxReadPacketLimits(t *testing.T) {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, uint32(kMuxMaxPacket+1))
	_, err := muxReadPacket(&buf)
	assert.ErrorContains(t, err, "exceeds maximum")

	buf.Reset()
	_ = binary.Write(&buf, binary.BigEndian, uint32(3))
	buf.Write([]byte{1, 2})
	_, err = muxReadPacket(&buf)
	assert.Error(t, err)
}

func TestMuxSshPacketFraming(t *testing.T) {
	var buf bytes.Buffer
	writer := &muxPacketWriter{w: &buf}
	require.NoError(t, writer.writeSshMessage(&sshChannelEOFMsg{PeersID: 9}))

	raw := buf.Bytes()
	assert.Equal(t, uint32(1+5), binary.BigEndian.Uint32(raw[:4]))
	assert.Equal(t, byte(0), raw[4]) // padding length
	assert.Equal(t, byte(kSshMsgChannelEOF), raw[5])

	payload, err := muxReadSshPacket(&buf)
	require.NoError(t, err)
	var msg sshChannelEOFMsg
	require.NoError(t, ssh.Unmarshal(payload, &msg))
	assert.Equal(t, uint32(9), msg.PeersID)

	// non-zero padding is rejected
	bad := []byte{0, 0, 0, 2, 1, kSshMsgChannelEOF}
	_, err = muxReadSshPacket(bytes.NewReader(bad))
	assert.Error(t, err)
}

func TestMuxSshMessageCopies(t *testing.T) {
	open := ssh.Marshal(&sshChannelOpenMsg{ChanType: "session", PeersID: 1, PeersWindow: 2, MaxPacketSize: 3})
	assert.Equal(t, byte(kSshMsgChannelOpen), open[0])
	var parsed sshChannelOpenMsg
	require.NoError(t, ssh.Unmarshal(open, &parsed))
	assert.Equal(t, "session", parsed.ChanType)
	assert.Equal(t, uint32(3), parsed.MaxPacketSize)

	req := ssh.Marshal(&sshChannelRequestMsg{PeersID: 5, Request: "exec", WantReply: true,
		RequestSpecificData: ssh.Marshal(&sshExecPayload{Command: "ls"})})
	assert.Equal(t, byte(kSshMsgChannelRequest), req[0])
	var parsedReq sshChannelRequestMsg
	require.NoError(t, ssh.Unmarshal(req, &parsedReq))
	var exec sshExecPayload
	require.NoError(t, ssh.Unmarshal(parsedReq.RequestSpecificData, &exec))
	assert.Equal(t, "ls", exec.Command)

	// a message with the wrong type byte must not unmarshal
	var eof sshChannelEOFMsg
	assert.Error(t, ssh.Unmarshal(open, &eof))
}

func TestParseTerminalModes(t *testing.T) {
	assert.Empty(t, parseTerminalModes(nil))
	assert.Empty(t, parseTerminalModes([]byte{kSshTerminalModeEnd}))

	var buf []byte
	buf = append(buf, ssh.ECHO)
	buf = binary.BigEndian.AppendUint32(buf, 1)
	buf = append(buf, ssh.TTY_OP_OSPEED)
	buf = binary.BigEndian.AppendUint32(buf, 115200)
	buf = append(buf, kSshTerminalModeEnd)
	buf = append(buf, ssh.ICANON) // after the terminator, must be ignored
	buf = binary.BigEndian.AppendUint32(buf, 1)

	modes := parseTerminalModes(buf)
	assert.Equal(t, ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_OSPEED: 115200}, modes)

	// truncated trailing entry is ignored
	assert.Equal(t, ssh.TerminalModes{ssh.ECHO: 1}, parseTerminalModes(buf[:7]))
}

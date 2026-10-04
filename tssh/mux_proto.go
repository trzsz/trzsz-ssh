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
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// OpenSSH multiplexing protocol constants.
// See https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.mux
const (
	kMuxProtocolVersion uint32 = 4

	kMuxMsgHello       uint32 = 0x00000001
	kMuxCNewSession    uint32 = 0x10000002
	kMuxCAliveCheck    uint32 = 0x10000004
	kMuxCTerminate     uint32 = 0x10000005
	kMuxCOpenFwd       uint32 = 0x10000006
	kMuxCCloseFwd      uint32 = 0x10000007
	kMuxCNewStdioFwd   uint32 = 0x10000008
	kMuxCStopListening uint32 = 0x10000009
	kMuxCProxy         uint32 = 0x1000000f

	kMuxSOk               uint32 = 0x80000001
	kMuxSPermissionDenied uint32 = 0x80000002
	kMuxSFailure          uint32 = 0x80000003
	kMuxSAlive            uint32 = 0x80000005
	kMuxSProxy            uint32 = 0x8000000f

	// kMuxHandshakeTimeout bounds the mux handshake and control commands.
	kMuxHandshakeTimeout = 10 * time.Second

	// kMuxMaxPacket is the maximum mux / proxied ssh packet size (same as x/crypto maxPacket).
	kMuxMaxPacket = 256 * 1024

	// kMuxChannelWindowSize is the initial window we grant to the peer on each channel.
	kMuxChannelWindowSize uint32 = 2 * 1024 * 1024
	// kMuxChannelMaxPacket is the maximum channel data packet size we accept and send.
	kMuxChannelMaxPacket uint32 = 32 * 1024

	// kMuxUdpModeRequest is the ssh global request a tssh slave sends to probe whether
	// the control master is a tssh UDP master (which replies success) or an OpenSSH
	// master (which forwards the request to sshd, which replies failure).
	kMuxUdpModeRequest = "udp-mode@trzsz.github.io"
)

// SSH connection protocol message numbers (RFC 4254).
const (
	kSshMsgGlobalRequest            = 80
	kSshMsgRequestSuccess           = 81
	kSshMsgRequestFailure           = 82
	kSshMsgChannelOpen              = 90
	kSshMsgChannelOpenConfirm       = 91
	kSshMsgChannelOpenFailure       = 92
	kSshMsgChannelWindowAdjust      = 93
	kSshMsgChannelData              = 94
	kSshMsgChannelExtendedData      = 95
	kSshMsgChannelEOF               = 96
	kSshMsgChannelClose             = 97
	kSshMsgChannelRequest           = 98
	kSshMsgChannelSuccess           = 99
	kSshMsgChannelFailure           = 100
	kSshExtendedDataStderr          = 1
	kSshTerminalModeEnd        byte = 0
)

// muxReadPacket reads one length-prefixed mux packet body.
func muxReadPacket(r io.Reader) ([]byte, error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(head[:])
	if length > kMuxMaxPacket {
		return nil, fmt.Errorf("mux packet length %d exceeds maximum %d", length, kMuxMaxPacket)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}

// muxWritePacket writes one length-prefixed mux packet in a single Write call.
func muxWritePacket(w io.Writer, body []byte) error {
	buf := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(buf, uint32(len(body)))
	copy(buf[4:], body)
	_, err := w.Write(buf)
	return err
}

// muxReadMessage reads a mux message and splits off its type.
func muxReadMessage(r io.Reader) (uint32, []byte, error) {
	body, err := muxReadPacket(r)
	if err != nil {
		return 0, nil, err
	}
	msgType, ok := muxReadUint32(&body)
	if !ok {
		return 0, nil, fmt.Errorf("mux message too short")
	}
	return msgType, body, nil
}

// muxBuildMessage encodes a mux message from uint32 and string fields.
func muxBuildMessage(msgType uint32, fields ...any) []byte {
	buf := binary.BigEndian.AppendUint32(nil, msgType)
	for _, field := range fields {
		switch v := field.(type) {
		case uint32:
			buf = binary.BigEndian.AppendUint32(buf, v)
		case string:
			buf = binary.BigEndian.AppendUint32(buf, uint32(len(v)))
			buf = append(buf, v...)
		default:
			panic(fmt.Sprintf("unsupported mux field type %T", field))
		}
	}
	return buf
}

// muxWriteMessage encodes and writes a mux message.
func muxWriteMessage(w io.Writer, msgType uint32, fields ...any) error {
	return muxWritePacket(w, muxBuildMessage(msgType, fields...))
}

// muxReadUint32 consumes a uint32 from the front of b.
func muxReadUint32(b *[]byte) (uint32, bool) {
	if len(*b) < 4 {
		return 0, false
	}
	v := binary.BigEndian.Uint32(*b)
	*b = (*b)[4:]
	return v, true
}

// muxReadString consumes an ssh string from the front of b.
func muxReadString(b *[]byte) (string, bool) {
	length, ok := muxReadUint32(b)
	if !ok || uint64(length) > uint64(len(*b)) {
		return "", false
	}
	s := string((*b)[:length])
	*b = (*b)[length:]
	return s, true
}

// muxReadSshPacket reads one proxied ssh packet: uint32 length, uint8 padding length (always 0), payload.
func muxReadSshPacket(r io.Reader) ([]byte, error) {
	body, err := muxReadPacket(r)
	if err != nil {
		return nil, err
	}
	if len(body) < 1 {
		return nil, fmt.Errorf("ssh packet missing padding length")
	}
	if body[0] != 0 {
		return nil, fmt.Errorf("ssh packet has unexpected padding length %d", body[0])
	}
	return body[1:], nil
}

// muxPacketWriter serializes writes of proxied ssh packets and mux messages to one connection.
type muxPacketWriter struct {
	mu sync.Mutex
	w  io.Writer
}

// writeSshPacket writes one proxied ssh packet (zero padding, no MAC) in a single Write call.
func (p *muxPacketWriter) writeSshPacket(payload []byte) error {
	if len(payload)+1 > kMuxMaxPacket {
		return fmt.Errorf("ssh packet length %d exceeds maximum %d", len(payload)+1, kMuxMaxPacket)
	}
	buf := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(buf, uint32(1+len(payload)))
	buf[4] = 0
	copy(buf[5:], payload)
	p.mu.Lock()
	defer p.mu.Unlock()
	_, err := p.w.Write(buf)
	return err
}

// writeSshMessage marshals an ssh message struct and writes it as a proxied ssh packet.
func (p *muxPacketWriter) writeSshMessage(msg any) error {
	return p.writeSshPacket(ssh.Marshal(msg))
}

// writeMuxMessage writes one mux protocol message.
func (p *muxPacketWriter) writeMuxMessage(msgType uint32, fields ...any) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return muxWriteMessage(p.w, msgType, fields...)
}

// Copies of the ssh connection protocol messages (the x/crypto types are unexported).
// The sshtype tags make ssh.Marshal / ssh.Unmarshal emit and check the message number.

type sshGlobalRequestMsg struct {
	Type      string `sshtype:"80"`
	WantReply bool
	Data      []byte `ssh:"rest"`
}

type sshRequestSuccessMsg struct {
	Data []byte `ssh:"rest" sshtype:"81"`
}

type sshRequestFailureMsg struct {
	Data []byte `ssh:"rest" sshtype:"82"`
}

type sshChannelOpenMsg struct {
	ChanType         string `sshtype:"90"`
	PeersID          uint32
	PeersWindow      uint32
	MaxPacketSize    uint32
	TypeSpecificData []byte `ssh:"rest"`
}

type sshChannelOpenConfirmMsg struct {
	PeersID          uint32 `sshtype:"91"`
	MyID             uint32
	MyWindow         uint32
	MaxPacketSize    uint32
	TypeSpecificData []byte `ssh:"rest"`
}

type sshChannelOpenFailureMsg struct {
	PeersID  uint32 `sshtype:"92"`
	Reason   ssh.RejectionReason
	Message  string
	Language string
}

type sshWindowAdjustMsg struct {
	PeersID         uint32 `sshtype:"93"`
	AdditionalBytes uint32
}

type sshChannelDataMsg struct {
	PeersID uint32 `sshtype:"94"`
	Length  uint32
	Rest    []byte `ssh:"rest"`
}

type sshChannelExtendedDataMsg struct {
	PeersID  uint32 `sshtype:"95"`
	Datatype uint32
	Length   uint32
	Rest     []byte `ssh:"rest"`
}

type sshChannelEOFMsg struct {
	PeersID uint32 `sshtype:"96"`
}

type sshChannelCloseMsg struct {
	PeersID uint32 `sshtype:"97"`
}

type sshChannelRequestMsg struct {
	PeersID             uint32 `sshtype:"98"`
	Request             string
	WantReply           bool
	RequestSpecificData []byte `ssh:"rest"`
}

type sshChannelSuccessMsg struct {
	PeersID uint32 `sshtype:"99"`
}

type sshChannelFailureMsg struct {
	PeersID uint32 `sshtype:"100"`
}

// Request and channel type specific payloads (no message number).

type sshPtyRequestPayload struct {
	Term     string
	Columns  uint32
	Rows     uint32
	Width    uint32
	Height   uint32
	Modelist []byte
}

type sshEnvPayload struct {
	Name  string
	Value string
}

type sshExecPayload struct {
	Command string
}

type sshSubsystemPayload struct {
	Subsystem string
}

type sshWindowChangePayload struct {
	Columns uint32
	Rows    uint32
	Width   uint32
	Height  uint32
}

type sshExitStatusPayload struct {
	Status uint32
}

type sshDirectTcpipPayload struct {
	RAddr string
	RPort uint32
	LAddr string
	LPort uint32
}

type sshDirectStreamLocalPayload struct {
	SocketPath string
	Reserved0  string
	Reserved1  uint32
}

type sshTcpipForwardPayload struct {
	Addr string
	Port uint32
}

type sshForwardedTcpipPayload struct {
	Addr       string
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

type sshStreamLocalForwardPayload struct {
	SocketPath string
}

type sshForwardedStreamLocalPayload struct {
	SocketPath string
	Reserved0  string
}

// parseTerminalModes decodes the encoded terminal modes of a pty-req (RFC 4254 section 8):
// a sequence of opcode byte + uint32 argument, terminated by TTY_OP_END (0).
func parseTerminalModes(modelist []byte) ssh.TerminalModes {
	modes := ssh.TerminalModes{}
	for len(modelist) >= 5 {
		opcode := modelist[0]
		if opcode == kSshTerminalModeEnd {
			break
		}
		modes[opcode] = binary.BigEndian.Uint32(modelist[1:5])
		modelist = modelist[5:]
	}
	return modes
}

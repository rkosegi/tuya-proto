/*
Copyright 2026 Richard Kosegi

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package proto

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
)

type messageBuilder struct {
	ver Version
	// for 3.5, this is function that generates IV
	ivGenFn func(pkt *Packet) []byte
	// function to derive session key
	sessEncFn encSessionKeyFn
}

type MessageCustomizer func(pkt *Packet)

func GenerateIvMsgC(ivGenFn func(pkt *Packet) []byte) MessageCustomizer {
	return func(pkt *Packet) {
		pkt.IV = ivGenFn(pkt)
	}
}

type BuilderOpt func(*messageBuilder)

func DeviceOriginated() MessageCustomizer {
	return func(pkt *Packet) {
		pkt.DeviceOriginated = true
	}
}

func WithIvGenFn(fn func(pkt *Packet) []byte) BuilderOpt {
	return func(b *messageBuilder) {
		b.ivGenFn = fn
	}
}

func DefaultIvGenFn() func(pkt *Packet) []byte {
	return func(pkt *Packet) []byte {
		out := make([]byte, ivLen35)
		if _, err := rand.Read(out); err != nil {
			panic(err)
		}
		return out
	}
}

func NewBuilder(ver Version, opts ...BuilderOpt) MessageBuilder {
	mb := &messageBuilder{ver: ver, sessEncFn: encSessionKeyPre35}
	for _, opt := range append([]BuilderOpt{
		WithIvGenFn(DefaultIvGenFn()),
	}, opts...) {
		opt(mb)
	}
	if ver == Version35 {
		mb.sessEncFn = encSessionKey35
	}
	return mb
}

func NewBuilder34() MessageBuilder34 {
	return NewBuilder(Version34).(MessageBuilder34)
}

func NewBuilder35(opts ...BuilderOpt) MessageBuilder34 {
	return NewBuilder(Version35, opts...).(MessageBuilder34)
}

type MessageBuilder interface {
	RequestAny(localKey []byte, payload any, seqNo uint32, cmdId CmdIdType, cfn ...MessageCustomizer) (*Packet, error)
	ResponseAny(localKey []byte, payload any, seqNo uint32, cmdId CmdIdType, cfn ...MessageCustomizer) (*Packet, error)
}

func (m *messageBuilder) RequestAny(localKey []byte, payload any, seqNo uint32, cmdId CmdIdType, cfn ...MessageCustomizer) (*Packet, error) {
	cfns := append([]MessageCustomizer{}, cfn...)
	if m.ver == Version35 {
		cfns = append(cfns, GenerateIvMsgC(m.ivGenFn))
	}

	return m.createAny(localKey, payload, seqNo, cmdId, cfns...)
}

func (m *messageBuilder) ResponseAny(localKey []byte, payload any, seqNo uint32, cmdId CmdIdType, cfn ...MessageCustomizer) (*Packet, error) {
	cfns := append([]MessageCustomizer{DeviceOriginated()}, cfn...)
	if m.ver == Version35 {
		cfns = append(cfns, GenerateIvMsgC(m.ivGenFn))
	}
	return m.createAny(localKey, payload, seqNo, cmdId, cfns...)
}

type MessageBuilder34 interface {
	MessageBuilder
	// SessKeyNegStart Session key negotiation start (step1) is sent by app/client. Nonce is randomly generated.
	SessKeyNegStart(localKey, clientNonce []byte, seqNo uint32) (*Packet, error)

	// SessKeyNegResult Session key negotiation result (step2) is sent by device.
	// It is expected that device already received clientNonce from step1.
	SessKeyNegResult(localKey, deviceNonce, clientNonce []byte, seqNo uint32) (*Packet, error)

	// SessKeyNegFinish Session key negotiation finish (step3) is sent by app/client.
	SessKeyNegFinish(localKey, deviceNonce []byte, seqNo uint32) (*Packet, error)

	// MakeSessionKey makes a session key using negotiated parameters
	MakeSessionKey(clientNonce, deviceNonce, localKey []byte) ([]byte, error)
}

func (m *messageBuilder) SessKeyNegStart(localKey, localNonce []byte, seqNo uint32) (*Packet, error) {
	if len(localNonce) != NonceLen {
		return nil, fmt.Errorf("invalid nonce length: %d, should be %d", len(localNonce), NonceLen)
	}
	var cfns []MessageCustomizer
	if m.ver == Version35 {
		cfns = append(cfns, GenerateIvMsgC(m.ivGenFn))
	}
	return m.create(localKey, localNonce, seqNo, CmdIdTypeSessKeyNegStart, cfns...)
}

// Session negotiation result is computed by device using its (remote) nonce and localKey (step 2).
// payload is encrypted 2-part buffer: 1, client nonce [16b] || 2, HMAC(deviceNonce) [32b]

func (m *messageBuilder) SessKeyNegResult(localKey, deviceNonce, clientNonce []byte, seqNo uint32) (*Packet, error) {
	var buff []byte
	cfns := []MessageCustomizer{DeviceOriginated()}

	if m.ver == Version35 {
		buff = append(buff, 0, 0, 0, 0)
		cfns = append(cfns, GenerateIvMsgC(m.ivGenFn))
	}
	buff = append(buff, deviceNonce...)
	buff = append(buff, hmacSha256(localKey, clientNonce)...)
	return m.create(localKey, buff, seqNo, CmdIdTypeSessKeyNegResult, cfns...)
}

// Session negotiation finish is sent by client (step 3)
// payload is HMAC(device nonce) [32b]

func (m *messageBuilder) SessKeyNegFinish(localKey, deviceNonce []byte, seqNo uint32) (*Packet, error) {
	if len(deviceNonce) != NonceLen {
		return nil, fmt.Errorf("invalid device nonce length: %d, should be %d", len(deviceNonce), NonceLen)
	}
	var cfns []MessageCustomizer
	if m.ver == Version35 {
		cfns = append(cfns, GenerateIvMsgC(m.ivGenFn))
	}

	return m.create(localKey, hmacSha256(localKey, deviceNonce), seqNo, CmdIdTypeSessKeyNegFinish, cfns...)
}

func (m *messageBuilder) MakeSessionKey(clientNonce, deviceNonce, localKey []byte) ([]byte, error) {
	return makeSessionKey(clientNonce, deviceNonce, localKey, m.sessEncFn)
}

func (m *messageBuilder) createAny(localKey []byte, payload any, seqNo uint32, cmdId CmdIdType, cfn ...MessageCustomizer) (*Packet, error) {
	var (
		data []byte
		err  error
	)
	switch payload.(type) {
	case string:
		data = []byte(payload.(string))
	case []byte:
		data = payload.([]byte)
	default:
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "")
		err = enc.Encode(payload)
		data = buf.Bytes()
	}
	if err != nil {
		return nil, err
	}
	return m.create(localKey, data, seqNo, cmdId, cfn...)
}

func (m *messageBuilder) create(localKey []byte, data []byte, seqNo uint32, cmdId CmdIdType, cfns ...MessageCustomizer) (*Packet, error) {
	var err error
	pkt := &Packet{
		Version:          m.ver,
		CmdId:            cmdId,
		DecryptedPayload: data,
		SeqNo:            seqNo,
	}
	for _, cfn := range cfns {
		cfn(pkt)
	}
	_, err = pkt.Encode(localKey)
	return pkt, err
}

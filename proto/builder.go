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
	"encoding/json"
	"fmt"
)

type messageBuilder struct {
	ver Version
}

type MessageCustomizer func(pkt *Packet)

func DeviceOriginated() MessageCustomizer {
	return func(pkt *Packet) {
		pkt.DeviceOriginated = true
	}
}

func NewBuilder(ver Version) MessageBuilder {
	return &messageBuilder{ver: ver}
}

func NewBuilder34() MessageBuilder34 {
	return NewBuilder(Version34).(MessageBuilder34)
}

type MessageBuilder interface {
	RequestAny(localKey []byte, payload any, seqNo uint32, cmdId CmdIdType) (*Packet, error)
	ResponseAny(localKey []byte, payload any, seqNo uint32, cmdId CmdIdType) (*Packet, error)
}

func (m *messageBuilder) RequestAny(localKey []byte, payload any, seqNo uint32, cmdId CmdIdType) (*Packet, error) {
	return m.createAny(localKey, payload, seqNo, cmdId)
}

func (m *messageBuilder) ResponseAny(localKey []byte, payload any, seqNo uint32, cmdId CmdIdType) (*Packet, error) {
	return m.createAny(localKey, payload, seqNo, cmdId, DeviceOriginated())
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
	if len(localNonce) != nonceLen {
		return nil, fmt.Errorf("invalid nonce length: %d, should be %d", len(localNonce), nonceLen)
	}
	return m.create(localKey, localNonce, seqNo, CmdIdTypeSessKeyNegStart)
}

// Session negotiation result is computed by device using its (remote) nonce and localKey (step 2).
// payload is encrypted 2-part buffer: 1, client nonce [16b] || 2, HMAC(deviceNonce) [32b]

func (m *messageBuilder) SessKeyNegResult(localKey, deviceNonce, clientNonce []byte, seqNo uint32) (*Packet, error) {
	var buff []byte
	buff = append(buff, deviceNonce...)
	buff = append(buff, hmacSha256(localKey, clientNonce)...)
	return m.create(localKey, buff, seqNo, CmdIdTypeSessKeyNegResult, func(pkt *Packet) {
		pkt.DeviceOriginated = true
	})
}

// Session negotiation finish is sent by client (step 3)
// payload is HMAC(device nonce) [32b]

func (m *messageBuilder) SessKeyNegFinish(localKey, deviceNonce []byte, seqNo uint32) (*Packet, error) {
	if len(deviceNonce) != nonceLen {
		return nil, fmt.Errorf("invalid device nonce length: %d, should be %d", len(deviceNonce), nonceLen)
	}
	return m.create(localKey, hmacSha256(localKey, deviceNonce), seqNo, CmdIdTypeSessKeyNegFinish)
}

func (m *messageBuilder) MakeSessionKey(clientNonce, deviceNonce, localKey []byte) ([]byte, error) {
	return makeSessionKey(clientNonce, deviceNonce, localKey)
}

func (m *messageBuilder) createAny(localKey []byte, payload any, seqNo uint32, cmdId CmdIdType, customizeFns ...MessageCustomizer) (*Packet, error) {
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
		data, err = json.Marshal(payload)
	}
	if err != nil {
		return nil, err
	}
	return m.create(localKey, data, seqNo, cmdId, customizeFns...)
}

func (m *messageBuilder) create(localKey []byte, data []byte, seqNo uint32, cmdId CmdIdType, customizeFns ...MessageCustomizer) (*Packet, error) {
	var err error
	pkt := &Packet{
		Version:          m.ver,
		CmdId:            cmdId,
		DecryptedPayload: data,
		SeqNo:            seqNo,
	}
	for _, cfn := range customizeFns {
		cfn(pkt)
	}
	_, err = pkt.Encode(localKey)
	return pkt, err
}

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
	"encoding/binary"
	"encoding/json"
)

// SetJsonPayload takes object and try to serialize it as JSON and put into packet.
func (p *Packet) SetJsonPayload(payload any) {
	w := bytes.Buffer{}
	enc := json.NewEncoder(&w)
	enc.SetIndent("", "")
	_ = enc.Encode(payload)
	p.DecryptedPayload = bytes.TrimSpace(w.Bytes())
}

// GetJsonPayload takes decrypted data and try to deserialize them into provided pointer type.
// Packet must be decrypted first.
func (p *Packet) GetJsonPayload(payload any) error {
	// trim leading garbage if data starts with version
	// 3.4            {"protocol":5,"t":1777961007,"data":{"dps":{"1":false}}}
	data := p.DecryptedPayload
	if bytes.Index(p.DecryptedPayload, []byte(p.Version.String())) == 0 {
		data = data[15:]
	}
	return json.NewDecoder(bytes.NewBuffer(data)).Decode(payload)
}

// UdpKey gets a key used to encrypt UDP broadcast packets
func UdpKey() []byte {
	return udpKey
}

func uint32AsBEBytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

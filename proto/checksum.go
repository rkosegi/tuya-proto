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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"hash/crc32"
	"slices"
)

func (p *Packet) checksum3133() bool {
	computed := p.computeCrc32()
	observed := binary.BigEndian.Uint32(p.Checksum)
	return computed == observed
}

func (p *Packet) checksum34(key []byte) bool {
	computed := p.computeHmacSha256(key)
	return slices.Equal(computed, p.Checksum)
}

func (p *Packet) computeCrc32() uint32 {
	var buff []byte
	buff = binary.BigEndian.AppendUint32(buff, p.Header)
	buff = binary.BigEndian.AppendUint32(buff, p.SeqNo)
	buff = binary.BigEndian.AppendUint32(buff, uint32(p.CmdId))
	buff = binary.BigEndian.AppendUint32(buff, p.DataLength)
	buff = append(buff, p.EncryptedPayload...)
	return crc32.ChecksumIEEE(buff)
}

func (p *Packet) computeHmacSha256(key []byte) []byte {
	var buff []byte
	buff = binary.BigEndian.AppendUint32(buff, p.Header)
	buff = binary.BigEndian.AppendUint32(buff, p.SeqNo)
	buff = binary.BigEndian.AppendUint32(buff, uint32(p.CmdId))
	buff = binary.BigEndian.AppendUint32(buff, p.DataLength)
	buff = append(buff, p.EncryptedPayload...)
	return hmacSha256(key, buff)
}

func hmacSha256(buf []byte, extra ...[]byte) []byte {
	h := hmac.New(sha256.New, buf)
	for _, ed := range extra {
		h.Write(ed)
	}
	return h.Sum(nil)
}

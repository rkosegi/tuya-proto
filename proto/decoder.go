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
	"encoding/binary"
	"fmt"
)

// Decode decodes and eventually decrypt buffer into this packet.
// Upon success, DecryptedPayload should contain plaintext data.
// Version should be set prior to calling this method.
func (p *Packet) Decode(data []byte, key []byte) error {
	p.bufferPos = 0
	// do some quick sanity checks, based on version and size of incoming data
	if p.Version == Version31 && len(data) < minLen31 {
		return fmt.Errorf("not enough data: %d, need at least %d", len(data), minLen31)
	}
	if p.Version == Version34 && len(data) < minLen34 {
		return fmt.Errorf("not enough data: %d, need at least %d", len(data), minLen34)
	}
	if p.Version == Version35 && len(data) < minLen35 {
		return fmt.Errorf("not enough data: %d, need at least %d", len(data), minLen35)
	}
	actualHeader := binary.BigEndian.Uint32(data[:LenHeaderMark])
	data = data[LenHeaderMark:]
	p.bufferPos += LenHeaderMark
	switch p.Version {
	case Version31, Version34:
		if actualHeader != Header31 {
			return fmt.Errorf("invalid packet header: 0x%x, expected 0x%x", actualHeader, Header31)
		}
		p.Header = Header31
		p.Footer = Footer31
		p.decodeCommon(data)
		return p.decode3134(data[LenCommonFields:], key)

	case Version35:
		if actualHeader != Header35 {
			return fmt.Errorf("invalid packet header: 0x%x, expected 0x%x", actualHeader, Header35)
		}
		p.Header = Header35
		p.Footer = Footer35
		// AAD is everything after header mark 006699 up to and including length field, so 14 bytes total
		p.AAD = data[:LenCommonFields+2]
		// skip 2 bytes (16‑bit reserved/unknown)
		data = data[2:]
		p.bufferPos = LenHeaderMark + 2
		p.decodeCommon(data)
		return p.decode35(data[LenCommonFields:], key)
	default:
		return fmt.Errorf("unknown version: %d", p.Version)
	}
}

func (p *Packet) decodeCommon(data []byte) {
	cur := 0
	p.SeqNo = binary.BigEndian.Uint32(data[cur : cur+uint32Size])
	cur += uint32Size
	p.CmdId = CmdIdType(binary.BigEndian.Uint32(data[cur : cur+uint32Size]))
	cur += uint32Size
	p.DataLength = binary.BigEndian.Uint32(data[cur : cur+uint32Size])
	cur += uint32Size
	p.bufferPos += cur
}

func (p *Packet) decode3134(data []byte, key []byte) error {
	dataAndChecksum := data[:int(p.DataLength)-LenFooterMark] // without footer, with checksum
	p.bufferPos += int(p.DataLength)

	data = data[int(p.DataLength)-LenFooterMark:]

	actualFooter := binary.BigEndian.Uint32(data[:LenFooterMark])
	if actualFooter != Footer31 {
		return fmt.Errorf("invalid packet footer: 0x%x, expected 0x%x", actualFooter, Footer31)
	}
	p.bufferPos += LenFooterMark

	// set only when device => client ?
	p.ReturnCode = binary.BigEndian.Uint32(dataAndChecksum[:uint32Size])
	if p.ReturnCode&0xFFFFFF00 == 0 {
		p.DeviceOriginated = true
	}

	// version 3.1, checksum is IEEE CRC, so just last 4 bytes
	p.ChecksumLen = uint32Size
	if p.Version == Version34 {
		// checksum is HMAC, 32 bytes
		p.ChecksumLen = hmac32Len
	}
	checksumPos := len(dataAndChecksum) - p.ChecksumLen
	p.EncryptedPayload = dataAndChecksum[:checksumPos]
	p.Checksum = dataAndChecksum[checksumPos:]
	switch p.Version {
	case Version31:
		p.ChecksumValid = p.checksum3133()
	case Version34:
		p.ChecksumValid = p.checksum34(key)
	}

	return p.decrypt31(key)
}

func (p *Packet) decrypt31(key []byte) (err error) {
	buff := p.EncryptedPayload
	// skip return code
	if p.ReturnCode&0xFFFFFF00 == 0 {
		buff = buff[uint32Size:]
	}
	if len(buff) > 0 {
		if p.DecryptedPayload, err = decryptAESCBC(key, buff); err != nil {
			return err
		}
	}
	return nil
}

func (p *Packet) decrypt35(key []byte) (err error) {
	if p.DecryptedPayload, err = decryptAESGCM(key, p.IV, p.Tag, p.EncryptedPayload, p.AAD); err != nil {
		return err
	}
	return nil
}

func (p *Packet) decode35(data, key []byte) error {
	// ignored 2 bytes
	p.IV = data[:ivLen35]
	data = data[ivLen35:]
	p.bufferPos += ivLen35
	// DataLen = len(iv)[12] + len(cipherText)[XX] + len(tag)[16]
	cipherTextLen := p.DataLength - (ivLen35 + tagLen35)
	p.EncryptedPayload = data[:cipherTextLen]
	p.bufferPos += int(cipherTextLen)
	data = data[cipherTextLen:]
	p.Tag = data[:tagLen35]
	p.bufferPos += tagLen35
	data = data[tagLen35:]
	actualFooter := binary.BigEndian.Uint32(data[:LenFooterMark])
	p.bufferPos += LenFooterMark
	if actualFooter != Footer35 {
		return fmt.Errorf("invalid packet footer: 0x%x, expected 0x%x", actualFooter, Footer35)
	}
	return p.decrypt35(key)
}

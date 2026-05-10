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
	"fmt"
	"io"
)

func (p *Packet) writeCommonFields(buff io.Writer) {
	_ = binary.Write(buff, binary.BigEndian, p.SeqNo)
	_ = binary.Write(buff, binary.BigEndian, p.CmdId)
	_ = binary.Write(buff, binary.BigEndian, p.DataLength)
	p.bufferPos += uint32Size * 3
}

func writeData(buff io.Writer, pkt *Packet) {
	_, _ = buff.Write(pkt.EncryptedPayload)
	pkt.bufferPos += len(pkt.EncryptedPayload)
}

func writeHeader3134(buff *bytes.Buffer, pkt *Packet) {
	pkt.Header = Header31
	buff.Write(uint32AsBEBytes(pkt.Header))
	pkt.bufferPos += LenHeaderMark
	pkt.DataLength += uint32(len(pkt.EncryptedPayload) + pkt.ChecksumLen + LenFooterMark)
	pkt.writeCommonFields(buff)
}

func encrypt31(pkt *Packet, key []byte) (err error) {
	if pkt.EncryptedPayload, err = encryptAESCBC(key, pkt.DecryptedPayload, true); err != nil {
		return
	}

	if pkt.DeviceOriginated {
		newData := make([]byte, len(pkt.EncryptedPayload)+uint32Size)
		binary.LittleEndian.PutUint32(newData, pkt.ReturnCode)
		copy(newData[uint32Size:], pkt.EncryptedPayload)
		pkt.EncryptedPayload = newData
		// pkt.DataLength += uint32Size
	}

	return nil
}

func writeChecksum31(buff *bytes.Buffer, pkt *Packet, _ []byte) {
	pkt.Checksum = binary.BigEndian.AppendUint32([]byte{}, pkt.computeCrc32())
	pkt.ChecksumValid = true
	buff.Write(pkt.Checksum)
	pkt.bufferPos += uint32Size
}

func writeChecksum34(buff *bytes.Buffer, pkt *Packet, key []byte) {
	pkt.Checksum = pkt.computeHmacSha256(key)
	pkt.ChecksumValid = true
	buff.Write(pkt.Checksum)
	pkt.bufferPos += hmac32Len
}

func writeFooter3134(buff *bytes.Buffer, pkt *Packet) {
	pkt.Footer = Footer31
	buff.Write(uint32AsBEBytes(pkt.Footer))
	pkt.bufferPos += LenFooterMark
}

func writeHeader35(buff *bytes.Buffer, pkt *Packet) {
	pkt.Header = Header35
	buff.Write(uint32AsBEBytes(pkt.Header))
	buff.Write([]byte{0, 0})
	pkt.bufferPos += LenHeaderMark + 2
	pkt.writeCommonFields(buff)
}

func writeFooter35(buff *bytes.Buffer, pkt *Packet) {
	pkt.Footer = Footer35
	buff.Write(uint32AsBEBytes(pkt.Footer))
	pkt.bufferPos += LenFooterMark
}

type encoder struct {
	// encrypts data, does not write anything to output buffer yet
	encryptFn func(pkt *Packet, key []byte) error
	// write header and leading fields
	writeHeaderFn func(buff *bytes.Buffer, pkt *Packet)
	// write encrypted data
	writeDataFn func(buff io.Writer, pkt *Packet)
	// write checksum/crc/hmac
	writeChecksumFn func(buff *bytes.Buffer, pkt *Packet, key []byte)
	// write footer
	writeFooterFn func(buff *bytes.Buffer, pkt *Packet)
}

// Encode encodes this packet content into buffer.
func (p *Packet) Encode(key []byte) ([]byte, error) {
	enc := &encoder{}
	var (
		buff bytes.Buffer
		err  error
	)
	p.bufferPos = 0
	p.DataLength = 0
	enc.writeDataFn = writeData

	switch p.Version {
	case Version31:
		p.ChecksumLen = uint32Size
		enc.writeHeaderFn = writeHeader3134
		enc.writeFooterFn = writeFooter3134
		enc.encryptFn = encrypt31
		enc.writeChecksumFn = writeChecksum31

	case Version34:
		p.ChecksumLen = hmac32Len
		enc.writeHeaderFn = writeHeader3134
		enc.writeFooterFn = writeFooter3134
		enc.encryptFn = encrypt31
		enc.writeChecksumFn = writeChecksum34

	case Version35:
		enc.writeHeaderFn = writeHeader35
		enc.writeFooterFn = writeFooter35
		enc.encryptFn = encrypt31
		enc.writeChecksumFn = writeChecksum31
	default:
		return nil, fmt.Errorf("unknown version: %d", p.Version)
	}

	if err = enc.encryptFn(p, key); err != nil {
		return nil, err
	}

	enc.writeHeaderFn(&buff, p)
	enc.writeDataFn(&buff, p)
	enc.writeChecksumFn(&buff, p, key)
	enc.writeFooterFn(&buff, p)
	p.encodedBuffer = buff.Bytes()
	return p.encodedBuffer, err
}

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
	"errors"
	"fmt"
	"strings"
)

const (
	Header31 = 0x000055aa
	Footer31 = 0x0000aa55
	Header35 = 0x00006699
	Footer35 = 0x00009966
)

var (
	footer3134 = []byte{0, 0, 0xaa, 0x55}
	udpKey     = []byte{
		0x6c, 0x1e, 0xc8, 0xe2, 0xbb, 0x9b, 0xb5, 0x9a,
		0xb5, 0x0b, 0x0d, 0xaf, 0x64, 0x9b, 0x41, 0x0a,
	}
	ErrMissingFooter3134 = errors.New("can't find packet footer 0x0000aa55 in buffer")
)

type (
	Version   int
	CmdIdType uint32
)

const (
	Version31 = Version(31)
	Version34 = Version(34)
	Version35 = Version(35)

	uint32Size    = 4
	LenHeaderMark = uint32Size
	LenFooterMark = uint32Size
	// LenCommonFields = seq(4) + cmd id(4) + len(4)
	LenCommonFields = 3 * uint32Size
	ivLen35         = 12
	tagLen35        = 16
	nonceLen        = 16
	hmac32Len       = 32
	// header(4) + seq(4) + cmd id(4) + len(4) + CRC(4) + footer(4)
	minLen31 = LenHeaderMark + LenCommonFields + uint32Size + LenFooterMark
	// header(4) + seq(4) + cmd id(4) + len(4) + HMAC(32) + footer(4) = 52
	minLen34 = LenHeaderMark + LenCommonFields + hmac32Len + LenFooterMark
	// header(4) + rsv(2) + seq(4) + cmd id(4) + len(4) + IV(12) + TAG(16) + footer(4) = 50
	minLen35 = LenHeaderMark + 2 + LenCommonFields + ivLen35 + tagLen35 + LenFooterMark
)

// https://github.com/codetheweb/tuyapi/blob/27f5bdb51fb80ab1f88505a304937767c4b70eb4/lib/message-parser.js#L14
const (
	CmdIdTypeUDP                   = CmdIdType(0)
	CmdIdTypeApConfig              = CmdIdType(1)
	CmdIdTypeActive                = CmdIdType(2)
	CmdIdTypeBind                  = CmdIdType(3)
	CmdIdTypeSessKeyNegStart       = CmdIdType(3)
	CmdIdTypeRenameGw              = CmdIdType(4)
	CmdIdTypeSessKeyNegResult      = CmdIdType(4)
	CmdIdTypeRenameDevice          = CmdIdType(5)
	CmdIdTypeSessKeyNegFinish      = CmdIdType(5)
	CmdIdTypeUnbind                = CmdIdType(6)
	CmdIdTypeControl               = CmdIdType(7)
	CmdIdTypeStatus                = CmdIdType(8)
	CmdIdTypeHeartBeat             = CmdIdType(9)
	CmdIdTypeDpQuery               = CmdIdType(10)
	CmdIdTypeQueryWifi             = CmdIdType(11)
	CmdIdTypeTokenBind             = CmdIdType(12)
	CmdIdTypeControlNew            = CmdIdType(13)
	CmdIdTypeEnableWifi            = CmdIdType(14)
	CmdIdTypeDpQueryNew            = CmdIdType(16)
	CmdIdTypeSceneExecute          = CmdIdType(17)
	CmdIdTypeDpRefresh             = CmdIdType(18)
	CmdIdTypeUDPNew                = CmdIdType(19)
	CmdIdTypeApConfigNew           = CmdIdType(20)
	CmdIdTypeBroadcastLpv34        = CmdIdType(35)
	CmdIdTypeBroadcastDevInfo      = CmdIdType(37)
	CmdIdTypeLANExtStream          = CmdIdType(40)
	CmdIdTypeLANGwActive           = CmdIdType(240)
	CmdIdTypeLANSubDevRequest      = CmdIdType(241)
	CmdIdTypeLANDeleteSubDev       = CmdIdType(242)
	CmdIdTypeLANReportSubDev       = CmdIdType(243)
	CmdIdTypeLANScene              = CmdIdType(244)
	CmdIdTypeLANPublishCloudConfig = CmdIdType(245)
	CmdIdTypeLANPublishAppConfig   = CmdIdType(246)
	CmdIdTypeLANExportAppConfig    = CmdIdType(247)
	CmdIdTypeLANPublishScenePanel  = CmdIdType(248)
	CmdIdTypeLANRemoveGw           = CmdIdType(249)
	CmdIdTypeLANCheckGwUpdate      = CmdIdType(250)
	CmdIdTypeLANGwUpdate           = CmdIdType(251)
	CmdIdTypeLANSetGwChannel       = CmdIdType(252)
)

type Packet struct {
	// Protocol version, must be set by caller prior to using Encode/Decode functions
	Version Version
	// Protocol header such as 0x000055aa (3.1-3.4) or 0x00006699 (3.5)
	Header uint32
	// Protocol footer such as 0x000055aa (3.1-3.4) or 0x00006699 (3.5)
	Footer uint32
	// local sequence number per session
	SeqNo uint32
	// Command ID
	CmdId CmdIdType
	// Length of data
	DataLength uint32
	// ciphertext content e.g. before inbound packet is decrypted or after outbound packet is encrypted.
	EncryptedPayload []byte
	// plain text content e.g. before encryption take place or after packet has been decrypted
	DecryptedPayload []byte
	// only set by device
	ReturnCode uint32
	// CRC32 or HMAC SHA
	Checksum []byte

	// protocol 3.5
	// IV 96-bit (12-byte) per-packet AES-GCM IV/nonce
	IV []byte
	// Tag 128-bit (16-byte) signature Tag value from AES-GCM encrypt-and-sign
	Tag []byte
	// GCM AAD
	AAD []byte

	// --- computed fields (not actually present in packet)

	// ChecksumValid is true upon validating checksum
	ChecksumValid bool

	// Length of checksum field
	ChecksumLen int
	// When true, then ReturnCode is included in data payload.
	// Only true when packet originates from device.
	DeviceOriginated bool

	// buffer position, used only for debugging
	bufferPos int

	encodedBuffer []byte
}

// Encoded makes a copy of lastly encoded buffer content.
func (p *Packet) Encoded() []byte {
	return bytes.Clone(p.encodedBuffer)
}

func (v Version) String() string {
	sb := strings.Builder{}
	sb.WriteString(fmt.Sprintf("%d", int(v)/10))
	sb.WriteRune('.')
	sb.WriteString(fmt.Sprintf("%d", int(v)%10))
	return sb.String()
}

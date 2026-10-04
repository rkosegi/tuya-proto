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
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
)

var (
	mb35              = NewBuilder35()
	tuyapi35ClNonce   = mustFromHex("169501790dbce30e211b4497d0968602")
	tuyapi35DevNonce  = []byte("49e9658e18943c19")
	tinytuya35ClNonce = mustFromHex("a802fb5401e0724d99b7f01c38a4e054")
	sessStart35AAD    = mustFromHex("000000000001000000030000002c")
	sessFin35AAD      = mustFromHex("00000000f703000000050000003c")
	iv35              = []byte("0123456789ab")
	tuyapiSessKey     = mustFromHex("7c2332535d59ebe44f5934f088905f3e")

	cmp35 = cmp.Comparer(func(x *Packet, y *Packet) bool {
		return x.Header == y.Header && x.CmdId == y.CmdId && x.DataLength == y.DataLength &&
			x.SeqNo == y.SeqNo && bytes.Equal(x.EncryptedPayload, y.EncryptedPayload) &&
			bytes.Equal(x.DecryptedPayload, y.DecryptedPayload) && bytes.Equal(x.AAD, y.AAD) &&
			bytes.Equal(x.Tag, y.Tag) && bytes.Equal(x.IV, y.IV)

	})
)

func TestDecode35Discovery(t *testing.T) {
	var (
		err error
		pkt *Packet
	)

	t.Run("Android Smart Home", func(t *testing.T) {
		pkt = &Packet{Version: Version35}
		err = pkt.Decode(mustFromHex(packet3_2), UdpKey())
		assert.Equal(t, CmdIdTypeBroadcastDevInfo, pkt.CmdId)
		assert.NoError(t, err)
		assert.Equal(t, uint32(63), pkt.DataLength)
		assert.Equal(t, []byte{0x1f, 0xc5, 0xdf, 0x4a, 0xc4, 0x2b, 0xa, 0xd4, 0xf8, 0xf0, 0x26, 0x68}, pkt.IV)
		assert.Len(t, pkt.DecryptedPayload, 35)
		assert.Equal(t, []byte(`{"from":"app","ip":"192.168.1.102"}`), pkt.DecryptedPayload)
	})
	t.Run("tinytuya", func(t *testing.T) {
		pkt = &Packet{Version: Version35}
		err = pkt.Decode(mustFromHex(packet3_3), UdpKey())
		assert.Equal(t, CmdIdTypeBroadcastDevInfo, pkt.CmdId)
		assert.NoError(t, err)
		assert.Equal(t, uint32(66), pkt.DataLength)
		assert.Equal(t, iv35, pkt.IV)
		assert.Len(t, pkt.DecryptedPayload, 38)
		assert.Equal(t, []byte(`{"from": "app", "ip": "192.168.1.109"}`), pkt.DecryptedPayload)
	})
}

func TestDecode35Invalid(t *testing.T) {
	var (
		err error
		pkt *Packet
	)
	pkt = &Packet{Version: Version35}
	t.Run("not enough data", func(t *testing.T) {
		err = pkt.Decode(mustFromHex(packet_bad35_1), nil)
		assert.Error(t, err)
	})
	t.Run("wrong header bytes", func(t *testing.T) {
		err = pkt.Decode(mustFromHex(strings.Repeat("0123456789", 10)), nil)
		assert.Error(t, err)
	})
}

func TestDecode35SessionNegStart(t *testing.T) {
	var (
		err  error
		pkt  *Packet
		pkt2 *Packet
	)
	t.Run("tinytuya", func(t *testing.T) {
		x := mustFromHex("00006699" +
			"000000000001000000030000002c" +
			"303132333435363738396162" +
			"b69ee21cc462d89809d8a99aefd72f83" +
			"5c7f6228562a1cb104111e0843619c44" +
			"00009966")
		pkt = &Packet{Version: Version35}
		err = pkt.Decode(x, key351)
		assert.Equal(t, CmdIdTypeSessKeyNegStart, pkt.CmdId)
		assert.NoError(t, err)
		assert.Equal(t, uint32(44), pkt.DataLength)
		assert.Equal(t, uint32(1), pkt.SeqNo)
		assert.Equal(t, iv35, pkt.IV)
		assert.Equal(t, sessStart35AAD, pkt.AAD)
		assert.Equal(t, mustFromHex("5c7f6228562a1cb104111e0843619c44"), pkt.Tag)

		mb35 = NewBuilder35(WithIvGenFn(func(_ *Packet) []byte {
			return pkt.IV
		}))
		if pkt2, err = mb35.SessKeyNegStart(key351, tinytuya35ClNonce, 1); err != nil {
			t.Error(err)
		}
		assert.True(t, cmp.Equal(pkt, pkt2, cmp35))
		assert.Equal(t, x, pkt2.Encoded())
	})
	t.Run("tuyapi cli", func(t *testing.T) {
		x := mustFromHex("00006699" +
			"000000000001000000030000002c" +
			"313738393939363933383030" +
			"253e7fa61f68ba5767b0f8432e4becef" +
			"9c1dad6d4a2e07aeccf9ee8962cf329d" +
			"00009966")
		pkt = &Packet{Version: Version35}
		err = pkt.Decode(x, key351)
		assert.Equal(t, CmdIdTypeSessKeyNegStart, pkt.CmdId)
		assert.NoError(t, err)
		assert.Equal(t, uint32(44), pkt.DataLength)
		assert.Equal(t, uint32(1), pkt.SeqNo)
		assert.Equal(t, []byte("178999693800"), pkt.IV)
		assert.Equal(t, sessStart35AAD, pkt.AAD)
		assert.Equal(t, false, pkt.DeviceOriginated)
		assert.Equal(t, mustFromHex("9c1dad6d4a2e07aeccf9ee8962cf329d"), pkt.Tag)
		assert.Equal(t, tuyapi35ClNonce, pkt.DecryptedPayload)

	})
}

func TestDecode35SessionNegResult(t *testing.T) {
	var (
		err  error
		pkt  *Packet
		pkt2 *Packet
	)
	t.Run("tuyapi cli", func(t *testing.T) {
		x := "00006699" +
			"00000000f7030000000400000050" +
			"6136c706f9a75a3695515933" +
			"21812222c59c3491f15dd247d3e59b30a6662e7a4b6ad68e14b954fe9e493e80c692ccbfa57df5c9a3efb65da5188124002366d7" +
			"c114ef23824250c4329fcdab2a812664" +
			"00009966"
		pkt = &Packet{Version: Version35}
		err = pkt.Decode(mustFromHex(x), key351)
		assert.NoError(t, err)
		assert.Equal(t, CmdIdTypeSessKeyNegResult, pkt.CmdId)
		assert.Equal(t, mustFromHex("6136c706f9a75a3695515933"), pkt.IV)
		assert.Equal(t, mustFromHex("00000000f7030000000400000050"), pkt.AAD)
		assert.Equal(t, uint32(80), pkt.DataLength)
		assert.Equal(t, uint32(63235), pkt.SeqNo)
		assert.Equal(t, uint32(0), pkt.ReturnCode)
		assert.Equal(t, true, pkt.DeviceOriginated)
		assert.Equal(t, mustFromHex("c114ef23824250c4329fcdab2a812664"), pkt.Tag)
		assert.Equal(t, mustFromHex("00000000"+
			"34396539363538653138393433633139"+
			"5a24f0b437d3affd65b87b8ee15672ad57ece7fa2ef65124ab3e9b8e14843197"), pkt.DecryptedPayload)

		deviceHmac := hmacSha256(key351, tuyapi35ClNonce)

		assert.Equal(t, mustFromHex("5a24f0b437d3affd65b87b8ee15672ad57ece7fa2ef65124ab3e9b8e14843197"), deviceHmac)

		mb35 = NewBuilder35(WithIvGenFn(func(p *Packet) []byte {
			if p.CmdId == CmdIdTypeSessKeyNegResult {
				return mustFromHex("6136c706f9a75a3695515933")
			}
			return DefaultIvGenFn()(p)
		}))

		if pkt2, err = mb35.SessKeyNegResult(key351, tuyapi35DevNonce, tuyapi35ClNonce, 63235); err != nil {
			t.Error(err)
		}
		assert.True(t, cmp.Equal(pkt, pkt2, cmp35))
	})
}

func TestDecode35SessionNegFinish(t *testing.T) {
	var (
		pkt, pkt2 *Packet
		err       error
	)

	t.Run("tinytuya", func(t *testing.T) {
		x := "00006699" +
			"000000000002000000050000003c" +
			"303132333435363738396162" +
			"1644aa111ffadce5ded2719f6c104819c02278276352880f858c94d81de52656" +
			"ba8004e22e32e51c1332d9a52747efcc" +
			"00009966"
		pkt = &Packet{Version: Version35}
		assert.NoError(t, pkt.Decode(mustFromHex(x), key351))
		assert.Equal(t, CmdIdTypeSessKeyNegFinish, pkt.CmdId)
		assert.Equal(t, uint32(60), pkt.DataLength)
		assert.Equal(t, uint32(2), pkt.SeqNo)
		assert.Equal(t, iv35, pkt.IV)
		assert.False(t, pkt.DeviceOriginated)
	})
	t.Run("tuya-cli", func(t *testing.T) {
		x := "00006699" +
			"00000000f703000000050000003c" +
			"313738393939363933383139" +
			"de8135208d85f723526769b374fa0ef55963025be85d50a8ccd1f40a6524e2b7" +
			"102fa249467918c53f03a556739c4950" +
			"00009966"

		civ := []byte("178999693819")
		pkt = &Packet{Version: Version35}
		assert.NoError(t, pkt.Decode(mustFromHex(x), key351))
		assert.Equal(t, CmdIdTypeSessKeyNegFinish, pkt.CmdId)
		assert.Equal(t, uint32(60), pkt.DataLength)
		assert.Equal(t, uint32(63235), pkt.SeqNo)
		assert.Equal(t, civ, pkt.IV)
		assert.False(t, pkt.DeviceOriginated)
		assert.Equal(t, sessFin35AAD, pkt.AAD)
		assert.Equal(t, mustFromHex("102fa249467918c53f03a556739c4950"), pkt.Tag)

		mb35 = NewBuilder35(WithIvGenFn(func(p *Packet) []byte {
			if p.CmdId == CmdIdTypeSessKeyNegFinish {
				return civ
			}
			return DefaultIvGenFn()(p)
		}))

		if pkt2, err = mb35.SessKeyNegFinish(key351, tuyapi35DevNonce, 63235); err != nil {
			t.Error(err)
		}
		assert.True(t, cmp.Equal(pkt, pkt2, cmp35))
	})
}

func TestMakeSessionKey35(t *testing.T) {
	xkey, err := mb35.MakeSessionKey(tuyapi35ClNonce, tuyapi35DevNonce, key351)
	assert.NoError(t, err)
	assert.Equal(t, tuyapiSessKey, xkey)
}

func TestDecode35DpQueryNewRequest(t *testing.T) {
	var pkt, pkt2 *Packet
	t.Run("tuyapi cli", func(t *testing.T) {
		x := "00006699" +
			"00000000f7040000001000000097" +
			"313738393939363933383139" +
			"84b5168f251f7908e99a16398c58b4fbb0436f8eeadea8a5d42c9a925358dc0ffe1c878d9f70f3b0ff6b687cdfac8cf92d3f22163d70da186def9b05f0352b9793751a4ddcc32c95b9ce044dc28bada2a81dbac4431b5e9043f0a601309b0372d325923a03bcf986a65268199ba75147ea844da415a815fb5eb066" +
			"14a3e5f95c2de465750e52c2a3ce7325" +
			"00009966"

		pkt = &Packet{Version: Version35}
		if err := pkt.Decode(mustFromHex(x), tuyapiSessKey); err != nil {
			t.Error(err)
		}
		assert.Equal(t, CmdIdTypeDpQueryNew, pkt.CmdId)
		assert.Equal(t, uint32(151), pkt.DataLength)
		assert.Equal(t, uint32(63236), pkt.SeqNo)
		assert.Equal(t, []byte("178999693819"), pkt.IV)
		assert.False(t, pkt.DeviceOriginated)

		var m map[string]any
		assert.NoError(t, pkt.GetJsonPayload(&m))
		t.Log(m)
		assert.Equal(t, "bf27c19ef5c8278ad83tbh", m["gwId"])

		mb35 = NewBuilder35(WithIvGenFn(func(p *Packet) []byte {
			if p.CmdId == CmdIdTypeDpQueryNew {
				return []byte("178999693819")
			}
			return DefaultIvGenFn()(p)
		}))

		var err error
		pkt2, err = mb35.RequestAny(tuyapiSessKey, `{"gwId":"bf27c19ef5c8278ad83tbh","devId":"bf27c19ef5c8278ad83tbh",`+
			`"t":"1789996938","dps":{},"uid":"bf27c19ef5c8278ad83tbh"}`, 63236, CmdIdTypeDpQueryNew)
		assert.NoError(t, err)
		assert.NotNil(t, pkt2)
		assert.True(t, cmp.Equal(pkt, pkt2, cmp35))
	})
}

func TestDecode35DpQueryNewResponse(t *testing.T) {
	var (
		err       error
		pkt, pkt2 *Packet
	)

	t.Run("tuyapi cli", func(t *testing.T) {
		x := "00006699" +
			"00000000f704000000100000006f" +
			"9b2fb9b5844f2f6c485a7d9f" +
			"5eab68b7ef7ad0d5830f4b552cdee786a455d48b9f1e0964582fbd3c3bedf720c5e7d0666ac36036820899427634a8f46d8bac756c648fccb9edd90a5589c5ad27f6dda3eca1b6e02719cf57ec3c3885225e2e" +
			"74799ad4ea6583873c092d5682e7fab3" +
			"00009966"
		pkt = &Packet{Version: Version35}
		if err = pkt.Decode(mustFromHex(x), tuyapiSessKey); err != nil {
			t.Error(err)
		}
		assert.Equal(t, CmdIdTypeDpQueryNew, pkt.CmdId)
		assert.Equal(t, uint32(111), pkt.DataLength)
		assert.Equal(t, uint32(63236), pkt.SeqNo)
		assert.Equal(t, mustFromHex("9b2fb9b5844f2f6c485a7d9f"), pkt.IV)
		assert.True(t, pkt.DeviceOriginated)

		var m map[string]any
		assert.NoError(t, pkt.GetJsonPayload(&m))
		t.Log(m)
		assert.Equal(t, float64(2401), m["dps"].(map[string]any)["20"])

		mb35 = NewBuilder35(WithIvGenFn(func(p *Packet) []byte {
			return pkt.IV
		}))
		pkt2, err = mb35.ResponseAny(tuyapiSessKey, `{"dps":{"1":true,"9":0,"17":1,"18":29,"19":27,"20":2401,"38":"on","101":false}}`,
			63236, CmdIdTypeDpQueryNew)
		assert.NoError(t, err)
		assert.True(t, cmp.Equal(pkt, pkt2, cmp35))
		// t.Log(cmp.Diff(pkt, pkt2, cmp35))
	})
}

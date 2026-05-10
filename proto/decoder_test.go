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
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecode31(t *testing.T) {
	var (
		err error
		pkt *Packet
		m   map[string]interface{}
	)

	t.Run("DpQuery request from app", func(t *testing.T) {
		pkt = &Packet{Version: Version31}
		err = pkt.Decode(mustFromHex(packet31Query, t), key1)
		assert.NoError(t, err)
		assert.Equal(t, true, pkt.ChecksumValid)
		assert.Equal(t, CmdIdTypeDpQuery, pkt.CmdId)
		assert.Equal(t, uint32(0), pkt.SeqNo)
		assert.Equal(t, uint32(88), pkt.DataLength)
		assert.Equal(t, 80, len(pkt.EncryptedPayload))
		m = mustDecodeJson(pkt.DecryptedPayload)
		assert.Equal(t, "bff9a1f18d1a16d1c5ekpd", m["gwId"])
		t.Log(string(pkt.DecryptedPayload))
	})

	t.Run("DpQuery response from device to controller #1", func(t *testing.T) {
		pkt = &Packet{Version: Version31}
		err = pkt.Decode(mustFromHex(packet31DpResp, t), key2)
		assert.NoError(t, err)
		assert.Equal(t, true, pkt.ChecksumValid)
		assert.Equal(t, CmdIdTypeDpQuery, pkt.CmdId)
		assert.Equal(t, uint32(140), pkt.DataLength)
		assert.Equal(t, 132, len(pkt.EncryptedPayload))
		t.Log(string(pkt.DecryptedPayload))
		m = mustDecodeJson(pkt.DecryptedPayload)["dps"].(map[string]interface{})
		assert.Equal(t, float64(155), m["19"])
		assert.Equal(t, "relay", m["39"])
	})

	t.Run("DpQuery response from device to controller #2", func(t *testing.T) {
		pkt = &Packet{Version: Version31}
		err = pkt.Decode(mustFromHex(packet31DpResp2, t), key3)
		assert.NoError(t, err)
		assert.Equal(t, true, pkt.ChecksumValid)
		assert.Equal(t, CmdIdTypeDpQuery, pkt.CmdId)
		t.Log(string(pkt.DecryptedPayload))
		m = mustDecodeJson(pkt.DecryptedPayload)["dps"].(map[string]interface{})
		assert.Equal(t, float64(110), m["19"])
		assert.Equal(t, "relay", m["39"])
	})

	t.Run("UDP broadcast from device (3.4)", func(t *testing.T) {
		pkt = &Packet{Version: Version31}
		err = pkt.Decode(mustFromHex(pkt_bcast_34, t), UdpKey())
		assert.NoError(t, err)
		assert.Equal(t, true, pkt.ChecksumValid)
		assert.Equal(t, CmdIdTypeBroadcastLpv34, pkt.CmdId)
		t.Log(string(pkt.DecryptedPayload))
		m = mustDecodeJson(pkt.DecryptedPayload)
		assert.NoError(t, err)
		assert.Equal(t, "bfc4c2312693b32a4eucga", m["gwId"])
		assert.Equal(t, "keyjup78v54myhan", m["productKey"])
	})

	t.Run("UDP broadcast from device (3.3)", func(t *testing.T) {
		pkt = &Packet{Version: Version31}
		err = pkt.Decode(mustFromHex(pkt_bcast_33, t), UdpKey())
		assert.NoError(t, err)
		assert.Equal(t, uint32(0), pkt.SeqNo)
		assert.Equal(t, true, pkt.ChecksumValid)
		assert.Equal(t, CmdIdTypeUDPNew, pkt.CmdId)
		t.Log(string(pkt.DecryptedPayload))
		m = mustDecodeJson(pkt.DecryptedPayload)
		assert.NoError(t, err)
		assert.Equal(t, "3.3", m["version"])
		assert.Equal(t, true, m["encrypt"])
		assert.Equal(t, "bf0a1798146145b0c6potc", m["gwId"])
		assert.Equal(t, "keym9qkuywghyrvs", m["productKey"])
	})
}

func TestDecode34(t *testing.T) {
	var (
		err error
		pkt *Packet
	)
	t.Run("session key negotiation", func(t *testing.T) {
		t.Run("start from app to device", func(t *testing.T) {
			pkt = &Packet{Version: Version34}
			err = pkt.Decode(mustFromHex(packet34_1, t), keyV34)
			assert.NoError(t, err)
			assert.Equal(t, CmdIdTypeSessKeyNegStart, pkt.CmdId)
			// payload is 16 bytes is client_nonce
			assert.Len(t, pkt.DecryptedPayload, nonceLen)
			assert.Equal(t, []byte(clientNonce34), pkt.DecryptedPayload)
			assert.True(t, pkt.ChecksumValid)
		})

		t.Run("result from device to app", func(t *testing.T) {
			pkt = &Packet{Version: Version34}
			err = pkt.Decode(mustFromHex(packet34_2, t), keyV34)
			assert.NoError(t, err)
			assert.Equal(t, uint32(64076), pkt.SeqNo)
			assert.Equal(t, CmdIdTypeSessKeyNegResult, pkt.CmdId)
			// first 16 bytes are remote(device) nonce
			assert.Equal(t, []byte(deviceNonce34), pkt.DecryptedPayload[:nonceLen])
			// next 32 bytes are HMAC-SHA256(local_key, local_nonce)
			assert.Equal(t, hmacSha256(keyV34, []byte(clientNonce34)), pkt.DecryptedPayload[nonceLen:nonceLen+hmac32Len])
			assert.True(t, pkt.ChecksumValid)
		})

		t.Run("finish from app to device", func(t *testing.T) {
			pkt = &Packet{Version: Version34}
			err = pkt.Decode(mustFromHex(packet34_3, t), keyV34)
			assert.Equal(t, uint32(2), pkt.SeqNo)
			assert.NoError(t, err)
			assert.Equal(t, CmdIdTypeSessKeyNegFinish, pkt.CmdId)
			// payload is HMAC-SHA256(local_key, device_nonce) [32b]
			assert.Len(t, pkt.DecryptedPayload, hmac32Len)
			assert.Equal(t, uint32(0x54), pkt.DataLength)
			assert.Equal(t, hmacSha256(keyV34, []byte(deviceNonce34)), pkt.DecryptedPayload)
			assert.True(t, pkt.ChecksumValid)
		})
	})

	t.Run("incomplete packet", func(t *testing.T) {
		pkt = &Packet{Version: Version34}
		err = pkt.Decode(mustFromHex(packet34_bad, t), keyV34)
		assert.Error(t, err)
	})

	t.Run("dp query", func(t *testing.T) {
		var xkey []byte
		xkey, err = makeSessionKey([]byte(clientNonce34), []byte(deviceNonce34), keyV34)
		assert.NoError(t, err)
		t.Log("\n" + hex.Dump(xkey))

		t.Run("request from app", func(t *testing.T) {
			pkt = &Packet{Version: Version34}
			err = pkt.Decode(mustFromHex(packet34_4, t), xkey)
			assert.NoError(t, err)
			assert.Equal(t, uint32(3), pkt.SeqNo)
			assert.Equal(t, CmdIdTypeDpQueryNew, pkt.CmdId)
			assert.Len(t, pkt.EncryptedPayload, 16)
			assert.Equal(t, []byte("{}"), pkt.DecryptedPayload)
		})

		t.Run("response from device", func(t *testing.T) {
			pkt = &Packet{Version: Version34}
			err = pkt.Decode(mustFromHex(packet34_5, t), xkey)
			assert.NoError(t, err)
			assert.Equal(t, uint32(0xfa4d), pkt.SeqNo)
			assert.Equal(t, CmdIdTypeDpQueryNew, pkt.CmdId)
			assert.Len(t, pkt.EncryptedPayload, 180)

			var m map[string]map[string]interface{}
			err = json.Unmarshal(pkt.DecryptedPayload, &m)
			assert.NoError(t, err)

			assert.Len(t, m["dps"], 17)
			assert.Equal(t, false, m["dps"]["1"])
			assert.Equal(t, float64(25375), m["dps"]["23"])
		})
	})

}

func TestDecode3134Invalid(t *testing.T) {
	var (
		err error
		pkt *Packet
	)
	for _, payload := range []string{
		packet31Bad1,
		packet_bad31_2,
		packet_bad31_3,
	} {
		pkt = &Packet{Version: Version31}
		err = pkt.Decode(mustFromHex(payload, t), nil)
		assert.Error(t, err)
	}
}

func TestDecode35Invalid(t *testing.T) {
	var (
		err error
		pkt *Packet
	)
	pkt = &Packet{Version: Version35}
	t.Run("not enough data", func(t *testing.T) {
		err = pkt.Decode(mustFromHex(packet_bad35_1, t), nil)
		assert.Error(t, err)
	})
	t.Run("wrong header bytes", func(t *testing.T) {
		err = pkt.Decode(mustFromHex(strings.Repeat("0123456789", 10), t), nil)
		assert.Error(t, err)
	})
}

func TestDecodeInvalid(t *testing.T) {
	t.Run("unknown version", func(t *testing.T) {
		pkt := &Packet{Version: Version(999)}
		assert.Error(t, pkt.Decode(mustFromHex(packet3_2, t), nil))
	})
}

func TestFullExchange34WithBuilder(t *testing.T) {
	var (
		pkt  *Packet
		pkt2 *Packet
		err  error
	)
	mb := NewBuilder34()
	pkt = &Packet{Version: Version34}

	t.Run("scenario set dps", func(t *testing.T) {
		t.Run("sess neg step #1", func(t *testing.T) {
			assert.NoError(t, pkt.Decode(mustFromHex(packet34SessNegStart, t), key342))
			assert.Equal(t, CmdIdTypeSessKeyNegStart, pkt.CmdId)
			localNonce := pkt.DecryptedPayload
			assert.NotNil(t, localNonce)
			pkt2, err = mb.SessKeyNegStart(key342, localNonce, 1)
			assert.NoError(t, err)
			assert.Equal(t, pkt.SeqNo, pkt2.SeqNo)
			assert.Equal(t, pkt.DecryptedPayload, pkt2.DecryptedPayload)
			assert.Equal(t, pkt.EncryptedPayload, pkt2.EncryptedPayload)
		})
		t.Run("sess neg step #2", func(t *testing.T) {
			assert.NoError(t, pkt.Decode(mustFromHex(packet34SessNegResult, t), key342))
			assert.Equal(t, CmdIdTypeSessKeyNegResult, pkt.CmdId)
			assert.True(t, pkt.DeviceOriginated)
			pkt2, err = mb.SessKeyNegResult(key342,
				[]byte(deviceNonce342),
				[]byte(clientNonce34), 56221)
			assert.NoError(t, err)
			assert.Equal(t, pkt.SeqNo, pkt2.SeqNo)
			assert.Equal(t, pkt.DecryptedPayload, pkt2.DecryptedPayload)
			assert.Equal(t, pkt.EncryptedPayload, pkt2.EncryptedPayload)
		})
		t.Run("sess neg step #3", func(t *testing.T) {
			assert.NoError(t, pkt.Decode(mustFromHex(packet34SessNegFinish, t), key342))
			assert.Equal(t, CmdIdTypeSessKeyNegFinish, pkt.CmdId)
			pkt2, err = mb.SessKeyNegFinish(key342, []byte(deviceNonce342), 2)
			assert.NoError(t, err)
			assert.Equal(t, pkt.SeqNo, pkt2.SeqNo)
			assert.Equal(t, pkt.DecryptedPayload, pkt2.DecryptedPayload)
			assert.Equal(t, pkt.EncryptedPayload, pkt2.EncryptedPayload)
		})
		t.Run("ControlNew request from app", func(t *testing.T) {
			var key []byte
			key, err = mb.MakeSessionKey([]byte(clientNonce34), []byte(deviceNonce342), key342)
			assert.NoError(t, pkt.Decode(mustFromHex(`000055aa000000030000000d00000074d2a0b5ff83447e220fae83e2e47869aa114d22ee0865c6731f8a025ac1d43920dfc0c602ed120ca494cfd1f97aa7e18e700b48d4090d14298bfec29f3b8a857befee391594295c460526789d67b3e16c46b9a01a70a737198f49ac7d39ea22b6abc7dacb44a9255c83cbff837f8763100000aa55`, t), key))
			assert.Equal(t, CmdIdTypeControlNew, pkt.CmdId)

			var m map[string]interface{}
			assert.NoError(t, pkt.GetJsonPayload(&m))
			t.Log(m)
			assert.Equal(t, float64(5), m["protocol"])
		})
		t.Run("Status response from device", func(t *testing.T) {
			var key []byte
			key, err = mb.MakeSessionKey([]byte(clientNonce34), []byte(deviceNonce342), key342)
			assert.NoError(t, pkt.Decode(mustFromHex(`000055aa0000db9e000000080000007800000000dd6fb2a0071202a3e744bafdbc52333bdd693dae44761c4db2f6792409b35d7736f000fdd1dbecf8ee5561496261b9aa770c06af1e75c229aae006d5663b95f540db94576dfc47114336e79652186a7915b97c8a779835ad9515033b22ac95077bad94791958a12a1ce690de891c8cf60000aa55`, t), key))
			assert.Equal(t, CmdIdTypeStatus, pkt.CmdId)
			assert.True(t, pkt.DeviceOriginated)

			var m map[string]interface{}
			assert.NoError(t, pkt.GetJsonPayload(&m))
			t.Log(m)
			assert.Equal(t, float64(4), m["protocol"])
		})
		t.Run("ControlNew ACK from device", func(t *testing.T) {
			resetPkt(pkt)
			var key []byte
			key, err = mb.MakeSessionKey([]byte(clientNonce34), []byte(deviceNonce342), key342)
			assert.NoError(t, pkt.Decode(mustFromHex(`000055aa0000db9f0000000d00000028000000002be21c9af40ac7bb04677e3c4489dc66f127cef377619d0ccb66a5a525177e450000aa55`, t), key))
			assert.Equal(t, CmdIdTypeControlNew, pkt.CmdId)
			assert.True(t, pkt.DeviceOriginated)
			assert.Equal(t, uint32(0), pkt.ReturnCode)
			assert.Equal(t, uint32(56223), pkt.SeqNo)
			assert.Len(t, pkt.DecryptedPayload, 0)
		})
	})
}

// 3.5 is still WIP

func TestDecode35(t *testing.T) {
	var (
		err error
		pkt *Packet
	)

	t.Run("UDP discovery request from app #1", func(t *testing.T) {
		pkt = &Packet{Version: Version35}
		err = pkt.Decode(mustFromHex(packet3_2, t), UdpKey())
		assert.Equal(t, CmdIdTypeBroadcastDevInfo, pkt.CmdId)
		assert.NoError(t, err)
		assert.Equal(t, uint32(63), pkt.DataLength)
		assert.Len(t, pkt.DecryptedPayload, 35)
		assert.Equal(t, []byte(`{"from":"app","ip":"192.168.1.102"}`), pkt.DecryptedPayload)
	})
	t.Run("UDP discovery request from app #2", func(t *testing.T) {
		pkt = &Packet{Version: Version35}
		err = pkt.Decode(mustFromHex(packet3_3, t), UdpKey())
		assert.Equal(t, CmdIdTypeBroadcastDevInfo, pkt.CmdId)
		assert.NoError(t, err)
		assert.Equal(t, uint32(66), pkt.DataLength)
		assert.Equal(t, []byte("0123456789ab"), pkt.IV)
		assert.Len(t, pkt.DecryptedPayload, 38)
		assert.Equal(t, []byte(`{"from": "app", "ip": "192.168.1.109"}`), pkt.DecryptedPayload)
	})
}

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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncode31(t *testing.T) {
	var (
		pkt  *Packet
		pkt2 *Packet
		err  error
		data []byte
	)

	t.Run("encode/decode", func(t *testing.T) {
		pkt = &Packet{Version: Version31}
		pkt2 = &Packet{Version: Version31}

		pkt.SetJsonPayload(map[string]interface{}{
			"gwId":  "bff9a1f18d1a16d1c5ekpd",
			"devId": "bff9a1f18d1a16d1c5ekpd",
		})
		pkt.CmdId = CmdIdTypeDpQuery
		data, err = pkt.Encode(key1)
		t.Log("\n" + hex.Dump(data))
		assert.NoError(t, err)
		assert.NotNil(t, data)

		err = pkt2.Decode(data, key1)
		assert.NoError(t, err)

		assert.Equal(t, uint32(88), pkt2.DataLength)

		assert.Equal(t, pkt.CmdId, pkt2.CmdId)
		assert.Equal(t, pkt.SeqNo, pkt2.SeqNo)
		assert.Equal(t, pkt.EncryptedPayload, pkt2.EncryptedPayload)
		assert.Equal(t, pkt.DecryptedPayload, pkt2.DecryptedPayload)
	})

	t.Run("invalid key", func(t *testing.T) {
		pkt = &Packet{Version: Version31}
		pkt2 = &Packet{Version: Version31}

		pkt.SetJsonPayload(map[string]interface{}{})
		pkt.CmdId = CmdIdTypeDpQuery
		data, err = pkt.Encode([]byte("a"))
		assert.Error(t, err)
	})
}

func TestEncodeMessageBuilder(t *testing.T) {
	var (
		pkt  *Packet
		err  error
		data []byte
	)
	t.Run("3.1", func(t *testing.T) {
		mb := NewBuilder(Version31)
		t.Run("DpQuery request from app", func(t *testing.T) {
			pkt, err = mb.RequestAny(key1,
				`{"gwId":"bff9a1f18d1a16d1c5ekpd","devId":"bff9a1f18d1a16d1c5ekpd"}`,
				uint32(0), CmdIdTypeDpQuery)
			assert.NoError(t, err)
			assert.NotNil(t, pkt)
			data = pkt.Encoded()
			assert.NotNil(t, data)
			assert.Equal(t, mustFromHex(packet31Query, t), data)
		})
		t.Run("DpQuery response from device", func(t *testing.T) {
			pkt, err = mb.ResponseAny(key2, `{"dps":{"1":true,"9":0,"18":131,"19":155,"20":2357,"26":0,"38":`+
				`"memory","39":"relay","40":false,"41":"","42":""}}`, uint32(0), CmdIdTypeDpQuery)
			assert.NoError(t, err)
			assert.NotNil(t, pkt)
			data = pkt.Encoded()
			assert.NotNil(t, data)
			assert.Equal(t, mustFromHex(packet31DpResp, t), data)
		})
	})
	t.Run("3.4", func(t *testing.T) {
		mb := NewBuilder34()

		t.Run("neg session start - invalid nonce", func(t *testing.T) {
			_, err = mb.SessKeyNegStart(nil, []byte(""), 15438)
			assert.Error(t, err)
		})

		t.Run("neg session start", func(t *testing.T) {
			pkt, err = mb.SessKeyNegStart(keyV34, []byte(clientNonce34), 1)
			assert.NoError(t, err)
			assert.NotNil(t, pkt)
			data = pkt.Encoded()
			assert.NotNil(t, data)
			t.Log("\n" + hex.Dump(data))
		})

		t.Run("neg session result", func(t *testing.T) {
			pkt, err = mb.SessKeyNegResult(keyV34, []byte(deviceNonce34), []byte(clientNonce34), 64076)
			assert.NoError(t, err)
			assert.Equal(t, []byte(deviceNonce34), pkt.DecryptedPayload[:nonceLen])
			assert.Equal(t, uint32(64076), pkt.SeqNo)
			data = pkt.Encoded()
			assert.NotNil(t, data)
			t.Log("\n" + hex.Dump(data))
		})

		t.Run("neg session finish", func(t *testing.T) {
			pkt, err = mb.SessKeyNegFinish(keyV34, []byte(deviceNonce34), 2)
			assert.NoError(t, err)
			assert.NotNil(t, data)
			assert.Equal(t, uint32(0x54), pkt.DataLength)
			assert.Equal(t, hmacSha256(keyV34, []byte(deviceNonce34)), pkt.DecryptedPayload)
			t.Log("\n" + hex.Dump(data))
		})

		t.Run("neg session finish - invalid nonce", func(t *testing.T) {
			_, err = mb.SessKeyNegFinish(nil, []byte(""), 15438)
			assert.Error(t, err)
		})
	})
}

func TestEncode35(t *testing.T) {
	var (
		pkt  *Packet
		err  error
		data []byte
	)
	pkt = &Packet{Version: Version35}
	pkt.SetJsonPayload(map[string]interface{}{})
	data, err = pkt.Encode(UdpKey())
	assert.NoError(t, err)
	assert.NotNil(t, data)
}

func TestEncodeInvalidVersion(t *testing.T) {
	pkt := &Packet{Version: Version(-1)}
	_, err := pkt.Encode(nil)
	assert.Error(t, err)
}

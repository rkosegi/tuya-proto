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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetJsonPayload(t *testing.T) {
	var pkt *Packet
	pkt = &Packet{}
	pkt.SetJsonPayload(map[string]interface{}{})
	assert.NotNil(t, pkt.DecryptedPayload)
	assert.Equal(t, "{}", string(pkt.DecryptedPayload))
}

func TestGetJsonPayload(t *testing.T) {
	var (
		pkt *Packet
		m   map[string]interface{}
		err error
	)
	pkt = &Packet{}
	pkt.DecryptedPayload = []byte(`{"a":123}`)
	err = pkt.GetJsonPayload(&m)
	assert.NoError(t, err)
	assert.Equal(t, float64(123), m["a"])

	pkt.DecryptedPayload = []byte("bla")
	err = pkt.GetJsonPayload(&m)
	assert.Error(t, err)
}

func TestMakeSessionKey(t *testing.T) {
	var (
		err error
		out []byte
	)
	t.Run("invalid", func(t *testing.T) {
		t.Run("local nonce length", func(t *testing.T) {
			_, err = makeSessionKey([]byte("abcdefgh"), []byte(deviceNonce34), keyV34)
			assert.Error(t, err)
		})
		t.Run("local key length", func(t *testing.T) {
			_, err = makeSessionKey([]byte(clientNonce34), []byte(deviceNonce34), []byte("A"))
			assert.Error(t, err)
		})
		t.Run("remote nonce length", func(t *testing.T) {
			_, err = makeSessionKey([]byte(clientNonce34), []byte("123"), keyV34)
			assert.Error(t, err)
		})
	})
	t.Run("valid", func(t *testing.T) {
		out, err = makeSessionKey([]byte(clientNonce34), []byte(deviceNonce34), keyV34)
		assert.NoError(t, err)
		assert.Equal(t, mustFromHex("aa9654767072bab3de272b4ae5fde9cc", t), out)
	})
}

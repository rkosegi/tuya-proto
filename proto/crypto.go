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
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func decryptAESGCM(key, iv, tag, ciphertext, aad []byte) ([]byte, error) {
	cb, err := aes.NewCipher(key)
	if err != nil {
		// KeySizeError
		return nil, err
	}

	gcm, err := cipher.NewGCM(cb)
	if err != nil {
		return nil, err
	}
	ciphertext = append(ciphertext, tag...)

	plaintext, err := gcm.Open(nil, iv, ciphertext, aad)
	if err != nil {
		return nil, err
	}
	return plaintext, err
}

func decryptAESCBC(key, encrypted []byte) ([]byte, error) {
	cb, err := aes.NewCipher(key)
	if err != nil {
		// KeySizeError
		return nil, err
	}
	out := make([]byte, len(encrypted))
	for i, j := 0, aes.BlockSize; i < len(encrypted); i, j = i+aes.BlockSize, j+aes.BlockSize {
		cb.Decrypt(out[i:j], encrypted[i:j])
	}
	return unpadPKCS7(out), nil
}

func encryptAESCBC(key, plaintext []byte, padding bool) ([]byte, error) {
	bc, err := aes.NewCipher(key)
	if err != nil {
		// KeySizeError
		return nil, err
	}
	if padding {
		plaintext = padPKCS7(plaintext, aes.BlockSize)
	}
	encrypted := make([]byte, len(plaintext))
	for i, j := 0, aes.BlockSize; i < len(plaintext); i, j = i+aes.BlockSize, j+aes.BlockSize {
		bc.Encrypt(encrypted[i:j], plaintext[i:j])
	}
	return encrypted, nil
}
func padPKCS7(buff []byte, blockSize int) []byte {
	padding := blockSize - len(buff)%blockSize
	padded := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(buff, padded...)
}

func unpadPKCS7(text []byte) []byte {
	padding := text[len(text)-1]
	return text[:len(text)-int(padding)]
}

func makeSessionKey(clientNonce, deviceNonce, localKey []byte) ([]byte, error) {
	if len(localKey) != aes.BlockSize {
		return nil, fmt.Errorf("invalid local key size: %d, must be %d", len(localKey), aes.BlockSize)
	}
	if len(clientNonce) != aes.BlockSize {
		return nil, fmt.Errorf("invalid client nonce size: %d, must be %d", len(clientNonce), aes.BlockSize)
	}
	if len(deviceNonce) != aes.BlockSize {
		return nil, fmt.Errorf("invalid device nonce size: %d, must be %d", len(deviceNonce), aes.BlockSize)
	}
	xkey := make([]byte, len(deviceNonce))
	for i := 0; i < len(deviceNonce); i++ {
		xkey[i] = deviceNonce[i] ^ clientNonce[i]
	}
	return encryptAESCBC(localKey, xkey, false)
}

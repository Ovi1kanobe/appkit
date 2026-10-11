// Package encryption encrypts credentials an application stores in its
// database, such as provider API keys, with the application's master key.
//
// It protects a leaked database file or backup, not a compromised running
// server. Losing the master key loses every value encrypted with it.
package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
)

const (
	keySize = 32
	version = 1
)

// ErrDecrypt means the value was altered, encrypted under another label, or
// encrypted with another key.
var ErrDecrypt = errors.New("encryption: cannot decrypt value")

// Key encrypts and decrypts values with AES-256-GCM.
type Key struct{ aead cipher.AEAD }

// ParseKey reads a base64-encoded 32-byte key, as made by `openssl rand -base64 32`.
func ParseKey(encoded string) (*Key, error) {
	secret, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(secret) != keySize {
		return nil, errors.New("encryption: the key must be 32 random bytes in base64; create one with openssl rand -base64 32")
	}
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Key{aead: aead}, nil
}

// Encrypt seals plaintext and binds it to label, which names where the value
// is stored, such as "billing.stripe_key" plus the row ID. Decrypt needs the
// same label, so a value copied to another row or field fails to decrypt.
func (key *Key) Encrypt(label, plaintext string) []byte {
	nonce := make([]byte, key.aead.NonceSize())
	rand.Read(nonce) // never fails
	sealed := append([]byte{version}, nonce...)
	return key.aead.Seal(sealed, nonce, []byte(plaintext), additionalData(label))
}

// Decrypt opens a value made by Encrypt with the same label.
func (key *Key) Decrypt(label string, sealed []byte) (string, error) {
	nonceSize := key.aead.NonceSize()
	if len(sealed) < 1+nonceSize+key.aead.Overhead() || sealed[0] != version {
		return "", ErrDecrypt
	}
	plaintext, err := key.aead.Open(nil, sealed[1:1+nonceSize], sealed[1+nonceSize:], additionalData(label))
	if err != nil {
		return "", ErrDecrypt
	}
	return string(plaintext), nil
}

func additionalData(label string) []byte {
	return append([]byte{version}, label...)
}

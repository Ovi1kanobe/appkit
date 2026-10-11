package encryption

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
)

func newKey(t *testing.T) *Key {
	secret := make([]byte, keySize)
	rand.Read(secret)
	key, err := ParseKey(base64.StdEncoding.EncodeToString(secret))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// TestEncryptedValuesStayBound checks round trips and every way a value must fail to decrypt.
func TestEncryptedValuesStayBound(t *testing.T) {
	key := newKey(t)
	sealed := key.Encrypt("billing.stripe_key:1", "sk_live_secret")
	if plaintext, err := key.Decrypt("billing.stripe_key:1", sealed); err != nil || plaintext != "sk_live_secret" {
		t.Fatalf("round trip: %q %v", plaintext, err)
	}
	if string(key.Encrypt("billing.stripe_key:1", "sk_live_secret")) == string(sealed) {
		t.Fatal("encrypting twice gave the same value")
	}
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 1
	for name, attempt := range map[string]func() (string, error){
		"other label": func() (string, error) { return key.Decrypt("billing.stripe_key:2", sealed) },
		"other key":   func() (string, error) { return newKey(t).Decrypt("billing.stripe_key:1", sealed) },
		"tampered":    func() (string, error) { return key.Decrypt("billing.stripe_key:1", tampered) },
		"truncated":   func() (string, error) { return key.Decrypt("billing.stripe_key:1", sealed[:5]) },
	} {
		if _, err := attempt(); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	for _, invalid := range []string{"", "not base64!", base64.StdEncoding.EncodeToString(make([]byte, 16))} {
		if _, err := ParseKey(invalid); err == nil {
			t.Fatalf("ParseKey(%q) accepted", invalid)
		}
	}
}

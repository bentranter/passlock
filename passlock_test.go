package passlock

import (
	"crypto/rand"
	"io"
	"strconv"
	"strings"
	"testing"
)

func TestNewEncryptionKey(t *testing.T) {
	t.Parallel()

	keyA := NewEncryptionKey()
	keyB := NewEncryptionKey()

	if keyA == keyB {
		t.Fatalf("Key %s should not equal %s\n", keyA, keyB)
	}

	if len(keyA) != 32 {
		t.Fatalf("Keys should be 32 bytes long, KeyA is %d bytes\n", len(keyA))
	}
}

func TestGenerateFromPassword_LongPassword(t *testing.T) {
	t.Parallel()

	key := NewEncryptionKey()
	longPassword := make([]byte, 128)
	_, err := io.ReadFull(rand.Reader, longPassword)
	if err != nil {
		t.Fatalf("Unexpected error reading from rand.Reader: %#v\n", err)
	}

	// Test that you can use 128 byte long password
	encryptedPassword, err := GenerateFromPassword(longPassword, DefaultCost, key)
	if err != nil {
		t.Fatalf("Unexpected error generating password: %#v\n", err)
	}
	err = CompareHashAndPassword(encryptedPassword, longPassword, key)
	if err != nil {
		t.Fatalf("Long passwords do not match: %#v\n", err)
	}
	err = CompareHashAndPassword(encryptedPassword, longPassword[:100], key)
	if err == nil {
		t.Fatalf("CompareHashAndPassword returned no error for mismatched long passwords:\n%s\nvs\n%s\n", longPassword, longPassword[:100])
	}
}

func TestGenerateFromPassword_DefaultCost(t *testing.T) {
	t.Parallel()

	key := NewEncryptionKey()
	password := []byte("password")

	// Test that work factor is at least the default cost, even if a smaller
	// value is passsed.
	encryptedPassword, err := GenerateFromPassword(password, 10, key)
	if err != nil {
		t.Fatalf("Unexpected error: %#v\n", err)
	}
	plainPassword, err := decrypt(encryptedPassword, key)
	if err != nil {
		t.Fatalf("Unexpected error: %#v\n", err)
	}
	if !strings.Contains(string(plainPassword), "$"+strconv.Itoa(DefaultCost)) {
		t.Fatalf("Password was hashed with a work factor lower than %d\n", DefaultCost)
	}
}

// Check stupid null character even though Go's bcrypt implementation protects
// against it.
func TestGenerateFromPassword_NulByte(t *testing.T) {
	t.Parallel()

	key := NewEncryptionKey()
	nullPasswordA := "abc/0123"
	nullPasswordB := "abc/0456"

	// Golang's bcrypt implementation already protects against this, but we'll
	// test it anyway as a sanity check.
	encryptedPassword, err := GenerateFromPassword([]byte(nullPasswordA), DefaultCost, key)
	if err != nil {
		t.Fatalf("Unexpected error: %#v\n", err)
	}
	err = CompareHashAndPassword(encryptedPassword, []byte(nullPasswordB), key)
	if err == nil {
		t.Fatalf("Passwords %s and %s are not the same, but appear to match\n", nullPasswordA, nullPasswordB)
	}
}

func TestRotateKey(t *testing.T) {
	t.Parallel()

	keyA := NewEncryptionKey()
	keyB := NewEncryptionKey()
	password := []byte("password")

	encryptedPassword, err := GenerateFromPassword(password, DefaultCost, keyA)
	if err != nil {
		t.Fatalf("Unexpected error hashing password: %#v\n", err)
	}

	newEncryptedPassword, err := RotateKey(keyA, keyB, encryptedPassword)
	if err != nil {
		t.Fatalf("Unexpected error rotating key: %#v\n", err)
	}

	err = CompareHashAndPassword(newEncryptedPassword, password, keyB)
	if err != nil {
		t.Fatalf("Expected password to match but got %#v\n", err)
	}

	err = CompareHashAndPassword(newEncryptedPassword, password, keyA)
	if err == nil {
		t.Fatalf("Expected decryption to fail.\n")
	}
}

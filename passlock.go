// Package passlock stores your passwords a tiny bit more safely than bcrypt alone.
package passlock

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"io"

	"golang.org/x/crypto/bcrypt"
)

// DefaultCost is the minimum work factor for bcrypt.
const DefaultCost = 14

// GenerateFromPassword hashes and salts a password from the given plaintext
// password and HMAC key.
func GenerateFromPassword(password []byte, cost int, key *[32]byte) ([]byte, error) {
	if cost < DefaultCost {
		cost = DefaultCost
	}

	encodedPassword, err := hashAndEncodePassword(password)
	if err != nil {
		return nil, err
	}

	// Now bcrypt it
	hashedPassword, err := bcrypt.GenerateFromPassword(encodedPassword, cost)
	if err != nil {
		return nil, err
	}

	// Now encrypt it
	return encrypt(hashedPassword, key)
}

// CompareHashAndPassword compares a hashed password to a plaintext password. It
// will return nil if the passwords match, and an error otherwise.
//
// This package wraps all the errors exported by the bcrypt package, so you
// won't need to import that package to compare errors.
func CompareHashAndPassword(encryptedPassword, password []byte, key *[32]byte) error {
	// decrypt hashedpassword TODO rename it encryptedPassword
	hashedPassword, err := decrypt(encryptedPassword, key)
	if err != nil {
		return err
	}

	encodedPassword, err := hashAndEncodePassword(password)
	if err != nil {
		return err
	}

	return bcrypt.CompareHashAndPassword(hashedPassword, encodedPassword)
}

// hashAndEncodePassword hashes a plaintext password using SHA384, and base64 encodes it.
func hashAndEncodePassword(password []byte) ([]byte, error) {
	hash := sha512.New512_256()
	_, err := hash.Write(password)
	if err != nil {
		return nil, err
	}
	hashedPassword := hash.Sum(nil)

	// Now base64 encode it
	encodedPassword := make([]byte, len(hashedPassword)*2)
	base64.StdEncoding.Encode(encodedPassword, hashedPassword)

	return encodedPassword, nil
}

// NewEncryptionKey generates a random 256-bit key for Encrypt() and
// Decrypt(). It panics if the source of randomness fails.
func NewEncryptionKey() *[32]byte {
	key := [32]byte{}
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		panic(err)
	}
	return &key
}

// encrypt encrypts data using 256-bit AES-GCM.  This both hides the content of
// the data and provides a check that it hasn't been altered. Output takes the
// form nonce|ciphertext|tag where '|' indicates concatenation.
func encrypt(plaintext []byte, key *[32]byte) (ciphertext []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// decrypt decrypts data using 256-bit AES-GCM.  This both hides the content of
// the data and provides a check that it hasn't been altered. Expects input
// form nonce|ciphertext|tag where '|' indicates concatenation.
func decrypt(ciphertext []byte, key *[32]byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil,
		ciphertext[:gcm.NonceSize()],
		ciphertext[gcm.NonceSize():],
		nil,
	)
}

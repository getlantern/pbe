// package pbe is an EXPERIMENTAL library for encrypting and decrypting messages
// using a secret key derived from a username and password. It uses PBKDF2 with
// SHA256 to derive the key from the password, using the username as the salt.
//
// Messages are encrypted and decrypted using authenticated encryption with
// code.google.com/p/go.crypto/nacl/secretbox. The nonce used for encryption is
// generated randomly using crypto/rand and prepended to the cipher text. On
// decryption the nonce is extracted from the head of the cipher text.
package pbe

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"code.google.com/p/go.crypto/nacl/secretbox"
	"code.google.com/p/go.crypto/pbkdf2"
)

// Key represents a password-derived key that can be used to encrypt and decrypt
// messages.
type Key struct {
	data *[32]byte
}

// New creates a new Key given the username and password, using the specified
// number of iterations for hashing in PBKDF2. As long as the same three
// parameters are specified to this function, the same Key is generated.
func New(username, password []byte, iterations int) *Key {
	var data [32]byte
	copy(data[:], pbkdf2.Key([]byte(password), []byte(username), iterations, 32, sha256.New))
	return &Key{&data}
}

// Encrypt encrypts the message and returns the cipher text.
func (key *Key) Encrypt(msg []byte) []byte {
	var nonce [24]byte
	rand.Reader.Read(nonce[:])
	return secretbox.Seal(nonce[:], msg, &nonce, key.data)
}

// EncryptToString is like Encrypt but returns a Base64 encoded version of the
// cipher text.
func (key *Key) EncryptToString(msg []byte) string {
	return base64.StdEncoding.EncodeToString(key.Encrypt(msg))
}

// Decrypt decrypts the cipher text and returns the plain text message.
func (key *Key) Decrypt(cipherText []byte) ([]byte, error) {
	var nonce [24]byte

	if len(cipherText) < 25 {
		return nil, fmt.Errorf("cipherText too short")
	}

	copy(nonce[:], cipherText[:24])
	decrypted, ok := secretbox.Open([]byte{}, cipherText[24:], &nonce, key.data)
	if !ok {
		return nil, fmt.Errorf("Unable to decrypt")
	}
	return decrypted, nil
}

// DecryptFromString is like Decrypt but accepts Base64 encoded cipher text.
func (key *Key) DecryptFromString(cipherText string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return nil, fmt.Errorf("Unable to decode base64 cipherText: %s", err)
	}
	return key.Decrypt(b)
}

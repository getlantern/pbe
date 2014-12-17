package pbe

import (
	"testing"

	"github.com/getlantern/testify/assert"
)

func TestRoundTrip(t *testing.T) {
	box := New([]byte("username"), []byte("password"), 5000)
	plainText := []byte("My Plain Text")
	cipherText := box.Encrypt(plainText)
	decrypted, err := box.Decrypt(cipherText)
	assert.NoError(t, err, "Decrypting should work")
	assert.Equal(t, plainText, decrypted, "Decrypted should match original plainText")
}

func TestTamper(t *testing.T) {
	box := New([]byte("username"), []byte("password"), 5000)
	plainText := []byte("My Plain Text")
	cipherText := box.Encrypt(plainText)
	cipherText[26] = cipherText[26] - 1
	_, err := box.Decrypt(cipherText)
	assert.Error(t, err, "Decrypting should fail")
}

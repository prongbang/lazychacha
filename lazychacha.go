package lazychacha

import (
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"

	cryptorand "crypto/rand"
)

type LazyChaCha interface {
	RandomKey() ([]byte, error)
	Encrypt(plaintext string, key []byte) (string, error)
	Decrypt(ciphertext string, key []byte) (string, error)
}

type lazyChaCha struct {
}

func (c *lazyChaCha) RandomKey() ([]byte, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := cryptorand.Read(key); err != nil {
		return []byte{}, err
	}
	return key, nil
}

func (c *lazyChaCha) Encrypt(plaintext string, key []byte) (string, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return "", err
	}

	// Select a random nonce, and leave capacity for the ciphertext.
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := cryptorand.Read(nonce); err != nil {
		return "", err
	}

	// Encrypt the message and append the ciphertext to the nonce.
	encrypted := aead.Seal(nonce, nonce, []byte(plaintext), nil)

	return hex.EncodeToString(encrypted), nil
}

func (c *lazyChaCha) Decrypt(ciphertext string, key []byte) (string, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aead.NonceSize() {
		return "", errors.New("ciphertext too short")
	}

	encrypted, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	// Split nonce and ciphertext.
	nonce, cipherbyte := encrypted[:aead.NonceSize()], encrypted[aead.NonceSize():]

	// Decrypt the message and check it wasn't tampered with.
	plaintext, err := aead.Open(nil, nonce, cipherbyte, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func New() LazyChaCha {
	return &lazyChaCha{}
}

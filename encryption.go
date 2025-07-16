package envelope

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"sort"
	"time"
)

// ErrCiphertextTooShort is returned when the ciphertext is too short to be valid.
var ErrCiphertextTooShort = errors.New("ciphertext too short")

// WithNonceSize sets the nonce size for the envelope.
func WithNonceSize(size int) Option {
	return func(e *Envelope) {
		if size <= 0 {
			size = 12 // Default nonce size for AES-GCM
		}

		e.nonceSize = size
	}
}

// Encrypt encrypts the envelope's data using AES-GCM and sets the FlagEncrypted flag.
func (e *Envelope) Encrypt(encryptionKey []byte) error {
	// Set the flag before encryption.
	e.SecurityFlags |= FlagEncrypted

	c, err := aes.NewCipher(encryptionKey)
	if err != nil {
		// If encryption fails, revert the flag.
		e.SecurityFlags &^= FlagEncrypted
		return err
	}

	gcm, err := cipher.NewGCMWithNonceSize(c, e.nonceSize)
	if err != nil {
		// If GCM setup fails, revert the flag.
		e.SecurityFlags &^= FlagEncrypted
		return err
	}

	nonce := make([]byte, e.nonceSize)
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		// If nonce generation fails, revert the flag.
		e.SecurityFlags &^= FlagEncrypted
		return err
	}

	aad, err := e.computeAAD()
	if err != nil {
		e.SecurityFlags &^= FlagEncrypted
		return err
	}

	e.Data = gcm.Seal(nonce, nonce, e.Data, aad)

	return nil
}

// Decrypt decrypts the envelope's data using AES-GCM if the FlagEncrypted is set.
func (e *Envelope) Decrypt(encryptionKey []byte) error {
	if e.SecurityFlags&FlagEncrypted == 0 {
		return nil
	}

	c, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCMWithNonceSize(c, e.nonceSize)
	if err != nil {
		return err
	}

	if len(e.Data) < e.nonceSize {
		return ErrCiphertextTooShort
	}

	aad, err := e.computeAAD()
	if err != nil {
		return err
	}

	nonce, ciphertext := e.Data[:e.nonceSize], e.Data[e.nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return err
	}

	e.Data = plaintext

	return nil
}

// computeAAD generates a deterministic byte slice from envelope metadata
// to be used as Associated Additional Data for AEAD ciphers.
func (e *Envelope) computeAAD() ([]byte, error) {
	// This can be a simplified version of your computeHMAC logic,
	// focusing on fields that should be authenticated but not encrypted.
	// For simplicity, we'll just use the ID and Metadata here.
	var b bytes.Buffer

	_, err := b.Write(e.ID)
	if err != nil {
		return nil, err
	}

	// Write Metadata in a deterministic order
	if e.Metadata != nil {
		keys := make([]string, 0, len(e.Metadata))
		for k := range e.Metadata {
			keys = append(keys, k)
		}

		sort.Strings(keys)

		for _, k := range keys {
			b.Write([]byte(k))
			b.Write([]byte(e.Metadata[k]))
		}
	}

	if !e.ExpiresAt.IsZero() {
		b.Write([]byte(e.ExpiresAt.Format(time.RFC3339)))
	}

	return b.Bytes(), nil
}

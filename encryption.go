package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// ErrCiphertextTooShort is returned when the ciphertext is too short to be valid.
var ErrCiphertextTooShort = errors.New("ciphertext too short")

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

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		// If GCM setup fails, revert the flag.
		e.SecurityFlags &^= FlagEncrypted
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		// If nonce generation fails, revert the flag.
		e.SecurityFlags &^= FlagEncrypted
		return err
	}

	e.Data = gcm.Seal(nonce, nonce, e.Data, nil)
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

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return err
	}

	nonceSize := gcm.NonceSize()
	if len(e.Data) < nonceSize {
		return ErrCiphertextTooShort
	}

	nonce, ciphertext := e.Data[:nonceSize], e.Data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}
	e.Data = plaintext
	return nil
}

package envelope

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"io"
	"sort"
	"time"

	"golang.org/x/crypto/sha3"
)

// ErrCiphertextTooShort is returned when the ciphertext is too short to be valid.
var ErrCiphertextTooShort = errors.New("ciphertext too short")

// ErrEnvelopeHasBeenTampered is returned when the envelope's signature is invalid.
var ErrEnvelopeHasBeenTampered = errors.New("envelope has been tampered with")

// ErrInvalidEnvelopeData is returned when the envelope data is invalid or corrupted.
var ErrInvalidEnvelopeData = errors.New("invalid envelope data")

// SecurityFlags is a bitmask that defines the security attributes of an envelope.
type SecurityFlags uint8

const (
	// FlagSigned indicates that the envelope is signed.
	FlagSigned SecurityFlags = 1 << iota
	// FlagEncrypted indicates that the envelope is encrypted.
	FlagEncrypted

	// CurrentVersion is the current version of the envelope format.
	CurrentVersion = 1
)

// Envelope is a container for data that can be signed and/or encrypted.
type Envelope struct {
	// Version of the envelope format, can be used for future compatibility
	Version uint16
	// ID is a unique identifier for the envelope.
	ID []byte
	// Data is the content of the envelope.
	Data []byte
	// Metadata is additional information about the envelope.
	Metadata map[string]string
	// TelemetryContext is a placeholder for telemetry information.
	TelemetryContext map[string]string
	// Signature is the signature of the data.
	Signature []byte
	// SecurityFlags define the security attributes of the envelope.
	SecurityFlags SecurityFlags
	// CreatedAt is the timestamp when the envelope was created.
	CreatedAt time.Time
	// ReceivedAt is the timestamp when the envelope was received.
	ReceivedAt time.Time
}

// New creates a new envelope with the given data and security flags.
// It initializes the envelope with the current version, timestamps, and empty maps.
func New(data []byte) *Envelope {
	return &Envelope{
		Version:          CurrentVersion,
		Data:             data,
		Metadata:         make(map[string]string),
		TelemetryContext: make(map[string]string),
		CreatedAt:        time.Now().UTC(),
	}
}

// MarshalBinary implements the encoding.BinaryMarshaler interface using gob.
func (e *Envelope) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)

	// Use a type alias to avoid recursive calls to MarshalBinary.
	type envelopeAlias Envelope
	if err := enc.Encode((*envelopeAlias)(e)); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface using gob.
func (e *Envelope) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)

	// Use a type alias to avoid recursive calls to UnmarshalBinary.
	type envelopeAlias Envelope
	return dec.Decode((*envelopeAlias)(e))
}

func (e *Envelope) computeHMAC(key []byte) ([]byte, error) {
	h := hmac.New(sha3.New384, key)

	versionBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(versionBytes, e.Version)
	_, err := h.Write(versionBytes)
	if err != nil {
		return nil, err
	}

	// Add SecurityFlags to the HMAC to prevent tampering
	_, err = h.Write([]byte{byte(e.SecurityFlags)})
	if err != nil {
		return nil, err
	}

	// Write ID and Data
	_, err = h.Write(e.ID)
	if err != nil {
		return nil, err
	}
	_, err = h.Write(e.Data)
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
			_, err = h.Write([]byte(k))
			if err != nil {
				return nil, err
			}
			_, err = h.Write([]byte(e.Metadata[k]))
			if err != nil {
				return nil, err
			}
		}
	}

	// Write TelemetryContext in a deterministic order
	if e.TelemetryContext != nil {
		keys := make([]string, 0, len(e.TelemetryContext))
		for k := range e.TelemetryContext {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			_, err = h.Write([]byte(k))
			if err != nil {
				return nil, err
			}
			_, err = h.Write([]byte(e.TelemetryContext[k]))
			if err != nil {
				return nil, err
			}
		}
	}

	// Write CreatedAt timestamp
	if !e.CreatedAt.IsZero() {
		b, err := e.CreatedAt.MarshalBinary()
		if err != nil {
			return nil, err
		}
		_, err = h.Write(b)
		if err != nil {
			return nil, err
		}
	}

	return h.Sum(nil), nil
}

// Sign generates a signature for the envelope's data and sets the FlagSigned flag.
func (e *Envelope) Sign(signingKey []byte) error {
	// Set the flag before computing the HMAC, as the flag is part of the signature.
	e.SecurityFlags |= FlagSigned
	sig, err := e.computeHMAC(signingKey)
	if err != nil {
		// If signing fails, revert the flag.
		e.SecurityFlags &^= FlagSigned
		return err
	}
	e.Signature = sig
	return nil
}

// Verify checks the signature of the envelope's data if the FlagSigned is set.
// If the flag is not set, it verifies that the signature is nil.
func (e *Envelope) Verify(signingKey []byte) error {
	if e.SecurityFlags&FlagSigned == 0 {
		if len(e.Signature) == 0 {
			return nil
		}
		return ErrEnvelopeHasBeenTampered
	}
	expectedSignature, err := e.computeHMAC(signingKey)
	if err != nil {
		return err
	}
	if !hmac.Equal(e.Signature, expectedSignature) {
		return ErrEnvelopeHasBeenTampered
	}
	return nil
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

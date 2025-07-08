package envelope

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/gob"
	"errors"
	"hash"
	"io"
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

// EnvelopeOption allows customization of Envelope creation.
type EnvelopeOption func(*Envelope)

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

	// --- Customization fields (unexported) ---
	hmacHashFunc func() hash.Hash
}

// New creates a new envelope with the given data and security flags.
// It initializes the envelope with the current version, timestamps, and empty maps.
func New(data []byte, opts ...EnvelopeOption) *Envelope {
	e := &Envelope{
		Version:          CurrentVersion,
		Data:             data,
		Metadata:         make(map[string]string),
		TelemetryContext: make(map[string]string),
		SecurityFlags:    0,
		CreatedAt:        time.Now().UTC(),

		// Set defaults
		hmacHashFunc: sha3.New384,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
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

package envelope

import (
	"bytes"
	"encoding/gob"
	"hash"
	"time"

	"golang.org/x/crypto/sha3"
)

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
	// ExpiresAt is the timestamp when the envelope expires.
	ExpiresAt time.Time

	// --- Customization fields (unexported) ---
	hmacHashFunc func() hash.Hash // Hash function used for HMAC computation
	nonceSize    int              // Size of the nonce for AES-GCM encryption
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
		nonceSize:    12,
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

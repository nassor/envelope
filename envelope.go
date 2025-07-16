// Package envelope provides a structure for creating, signing, and encrypting data envelopes.
// It supports CBOR serialization and includes options for security features like signing and encryption.
// The Envelope struct contains fields for versioning, data, metadata, security flags, timestamps, and more.
package envelope

import (
	"hash"
	"time"

	"github.com/fxamacker/cbor/v2"
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

var cborEnc cbor.EncMode

func init() {
	opts := cbor.CoreDetEncOptions()

	opts.Time = cbor.TimeRFC3339Nano
	opts.Sort = cbor.SortCTAP2

	var err error

	cborEnc, err = opts.EncMode()
	if err != nil {
		panic("failed to initialize CBOR encoding options: " + err.Error())
	}
}

// Option allows customization of Envelope creation.
type Option func(*Envelope)

// Envelope is a container for data that can be signed and/or encrypted.
type Envelope struct {
	// Version of the envelope format, can be used for future compatibility
	Version uint16
	// ID is a unique identifier for the envelope.
	ID []byte
	// Data is the content of the envelope.
	Data []byte
	// Metadata is additional information about the envelope.
	Metadata map[string]string `cbor:",omitempty"`
	// TelemetryContext is a placeholder for telemetry information.
	TelemetryContext map[string]string `cbor:",omitempty"`
	// Signature is the signature of the data.
	Signature []byte `cbor:",omitempty"`
	// SecurityFlags define the security attributes of the envelope.
	SecurityFlags SecurityFlags
	// CreatedAt is the timestamp when the envelope was created.
	CreatedAt time.Time
	// ReceivedAt is the timestamp when the envelope was received.
	ReceivedAt time.Time `cbor:"-"`
	// ExpiresAt is the timestamp when the envelope expires.
	ExpiresAt time.Time `cbor:",omitzero"`

	// --- Customization fields (unexported) ---
	// Hash function used for HMAC computation
	hmacHashFunc func() hash.Hash `cbor:"-"`
	// Size of the nonce for AES-GCM encryption
	nonceSize int `cbor:"-"`
}

// New creates a new envelope with the given data and security flags.
// It initializes the envelope with the current version, timestamps, and empty maps.
func New(data []byte, opts ...Option) *Envelope {
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

// Empty creates a new envelope with no data.
func Empty(opts ...Option) *Envelope {
	return New(nil, opts...)
}

// MarshalBinary implements the encoding.BinaryMarshaler interface using cbor.
func (e *Envelope) MarshalBinary() ([]byte, error) {
	type envelopeAlias Envelope
	return cborEnc.Marshal((*envelopeAlias)(e))
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface using cbor.
func (e *Envelope) UnmarshalBinary(data []byte) error {
	// Use a type alias to avoid recursive calls to UnmarshalBinary.
	type envelopeAlias Envelope
	return cbor.Unmarshal(data, (*envelopeAlias)(e))
}

// Seal encrypts and signs the envelope, finalizing its contents.
func (e *Envelope) Seal(encryptionKey, signingKey []byte) error {
	if encryptionKey != nil {
		if err := e.Encrypt(encryptionKey); err != nil {
			return err
		}
	}

	if signingKey != nil {
		if err := e.Sign(signingKey); err != nil {
			return err
		}
	}

	return nil
}

// Unseal verifies and decrypts the envelope, restoring its original contents.
func (e *Envelope) Unseal(encryptionKey, signingKey []byte) error {
	if e.SecurityFlags&FlagSigned != 0 {
		if err := e.Verify(signingKey); err != nil {
			return err
		}
	}

	if e.SecurityFlags&FlagEncrypted != 0 {
		if err := e.Decrypt(encryptionKey); err != nil {
			return err
		}
	}

	// Update ReceivedAt to current time after unsealing
	e.ReceivedAt = time.Now().UTC()

	return nil
}

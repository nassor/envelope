package envelope

import (
	"hash"
	"time"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/sha3"
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
	Metadata map[string]string `json:",omitempty"`
	// TelemetryContext is a placeholder for telemetry information.
	TelemetryContext map[string]string `json:",omitempty"`
	// Signature is the signature of the data.
	Signature []byte `json:",omitempty"`
	// SecurityFlags define the security attributes of the envelope.
	SecurityFlags SecurityFlags
	// CreatedAt is the timestamp when the envelope was created.
	CreatedAt time.Time
	// ExpiresAt is the timestamp when the envelope expires.
	ExpiresAt time.Time `json:",omitzero"`

	// --- Customization fields (unexported) ---
	// Hash function used for HMAC computation
	hmacHashFunc func() hash.Hash `cbor:"-"`
	// Size of the nonce for AES-GCM encryption
	nonceSize int `cbor:"-"`
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

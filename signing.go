package envelope

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"hash"
	"sort"
)

// ErrEnvelopeHasBeenTampered is returned when the envelope's signature is invalid.
var ErrEnvelopeHasBeenTampered = errors.New("envelope has been tampered with")

// WithHMACHash sets the HMAC hash function for the envelope.
func WithHMACHash(hashFunc func() hash.Hash) EnvelopeOption {
	return func(e *Envelope) {
		e.hmacHashFunc = hashFunc
	}
}

// computeHMAC uses the selected hash function.
func (e *Envelope) computeHMAC(key []byte) ([]byte, error) {
	h := hmac.New(e.hmacHashFunc, key)

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

	// Write ExpiresAt timestamp
	if !e.ExpiresAt.IsZero() {
		b, err := e.ExpiresAt.MarshalBinary()
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

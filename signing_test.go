package envelope

import (
	"crypto/sha256"
	"errors"
	"hash"
	"testing"
	"time"
)

func TestEnvelope_Sign(t *testing.T) {
	t.Parallel()

	testData := []byte("some data")

	t.Run("OK", func(t *testing.T) {
		e := New(testData)
		err := e.Sign(nil)
		if err != nil {
			t.Fatalf("Failed to sign payload: %v", err)
		}
	})

	t.Run("CustomHashFunc", func(t *testing.T) {
		hashFunc := sha256.New
		e := New(testData, WithHMACHash(hashFunc))

		err := e.Sign(nil)
		if err != nil {
			t.Fatalf("Failed to sign payload: %v", err)
		}
	})
}

func TestEnvelope_Verify(t *testing.T) {
	t.Parallel()

	testData := []byte("some data")

	t.Run("OK", func(t *testing.T) {
		e := New(testData)
		err := e.Sign(nil)
		if err != nil {
			t.Fatalf("Failed to sign payload: %v", err)
		}

		err = e.Verify(nil)
		if err != nil {
			t.Fatalf("Failed to verify signature: %v", err)
		}

		if e.Signature == nil {
			t.Fatal("Expected a signature, but got nil")
		}
	})

	t.Run("Tampered", func(t *testing.T) {
		e := New(testData)
		err := e.Sign(nil)
		if err != nil {
			t.Fatalf("Failed to sign payload: %v", err)
		}

		// Tamper with the signature.
		e.Signature[0] ^= 0xff

		err = e.Verify(nil)
		if err == nil {
			t.Fatal("Expected an error, but got nil")
		}
	})

	t.Run("TamperVersion", func(t *testing.T) {
		e := New(testData)
		if err := e.Sign(nil); err != nil {
			t.Fatalf("Failed to sign payload: %v", err)
		}
		e.Version++
		err := e.Verify(nil)
		if !errors.Is(err, ErrEnvelopeHasBeenTampered) {
			t.Fatalf("Verify() error = %v, want %v for tampered Version", err, ErrEnvelopeHasBeenTampered)
		}
	})

	t.Run("TamperSecurityFlags", func(t *testing.T) {
		e := New(testData)
		if err := e.Sign(nil); err != nil {
			t.Fatalf("Failed to sign payload: %v", err)
		}
		e.SecurityFlags |= FlagEncrypted
		err := e.Verify(nil)
		if !errors.Is(err, ErrEnvelopeHasBeenTampered) {
			t.Fatalf("Verify() error = %v, want %v for tampered SecurityFlags", err, ErrEnvelopeHasBeenTampered)
		}
	})

	t.Run("TamperID", func(t *testing.T) {
		e := New(testData)
		e.ID = []byte("test-id")
		if err := e.Sign(nil); err != nil {
			t.Fatalf("Failed to sign payload: %v", err)
		}
		e.ID[0] ^= 0xff
		err := e.Verify(nil)
		if !errors.Is(err, ErrEnvelopeHasBeenTampered) {
			t.Fatalf("Verify() error = %v, want %v for tampered ID", err, ErrEnvelopeHasBeenTampered)
		}
	})

	t.Run("TamperData", func(t *testing.T) {
		e := New(testData)
		if err := e.Sign(nil); err != nil {
			t.Fatalf("Failed to sign payload: %v", err)
		}
		e.Data[0] ^= 0xff
		err := e.Verify(nil)
		if !errors.Is(err, ErrEnvelopeHasBeenTampered) {
			t.Fatalf("Verify() error = %v, want %v for tampered Data", err, ErrEnvelopeHasBeenTampered)
		}
	})

	t.Run("TamperMetadata", func(t *testing.T) {
		e := New(testData)
		e.Metadata["key"] = "value"
		if err := e.Sign(nil); err != nil {
			t.Fatalf("Failed to sign payload: %v", err)
		}
		e.Metadata["key"] = "new-value"
		err := e.Verify(nil)
		if !errors.Is(err, ErrEnvelopeHasBeenTampered) {
			t.Fatalf("Verify() error = %v, want %v for tampered Metadata", err, ErrEnvelopeHasBeenTampered)
		}
	})

	t.Run("TamperTelemetryContext", func(t *testing.T) {
		e := New(testData)
		e.TelemetryContext["key"] = "value"
		if err := e.Sign(nil); err != nil {
			t.Fatalf("Failed to sign payload: %v", err)
		}
		e.TelemetryContext["key"] = "new-value"
		err := e.Verify(nil)
		if !errors.Is(err, ErrEnvelopeHasBeenTampered) {
			t.Fatalf("Verify() error = %v, want %v for tampered TelemetryContext", err, ErrEnvelopeHasBeenTampered)
		}
	})

	t.Run("TamperCreatedAt", func(t *testing.T) {
		e := New(testData)
		if err := e.Sign(nil); err != nil {
			t.Fatalf("Failed to sign payload: %v", err)
		}
		e.CreatedAt = e.CreatedAt.Add(1 * time.Minute)
		err := e.Verify(nil)
		if !errors.Is(err, ErrEnvelopeHasBeenTampered) {
			t.Fatalf("Verify() error = %v, want %v for tampered CreatedAt", err, ErrEnvelopeHasBeenTampered)
		}
	})

	t.Run("TamperExpiresAt", func(t *testing.T) {
		e := New(testData)
		e.ExpiresAt = time.Now().Add(1 * time.Hour)
		err := e.Sign(nil)
		if err != nil {
			t.Fatalf("Failed to sign payload: %v", err)
		}

		// Tamper with the ExpiresAt field.
		e.ExpiresAt = e.ExpiresAt.Add(1 * time.Minute)

		err = e.Verify(nil)
		if !errors.Is(err, ErrEnvelopeHasBeenTampered) {
			t.Fatalf("Verify() error = %v, want %v for tampered ExpiresAt", err, ErrEnvelopeHasBeenTampered)
		}
	})
}

// errorHash is a mock hash.Hash that always returns an error on Write.
type errorHash struct {
	hash.Hash
}

func (e errorHash) Write(p []byte) (n int, err error) {
	return 0, errors.New("forced write error")
}

func newErrorHash() hash.Hash { return errorHash{sha256.New()} }

func TestHMACErrorCases(t *testing.T) {
	t.Parallel()

	testData := []byte("some data")

	t.Run("SignWriteError", func(t *testing.T) {
		e := New(testData, WithHMACHash(newErrorHash))

		err := e.Sign(nil)
		if err == nil {
			t.Fatal("Expected an error, but got nil")
		}
	})
}

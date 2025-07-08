package envelope

import (
	"crypto/sha256"
	"errors"
	"hash"
	"testing"
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

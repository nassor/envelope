package envelope

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func TestCombined(t *testing.T) {
	signingKey := make([]byte, 32)
	_, err := rand.Read(signingKey)
	if err != nil {
		t.Fatalf("Failed to generate signing key: %v", err)
	}
	encryptionKey := make([]byte, 32)
	_, err = rand.Read(encryptionKey)
	if err != nil {
		t.Fatalf("Failed to generate encryption key: %v", err)
	}
	originalData := []byte("very secret data")

	e := New(bytes.Clone(originalData))
	err = e.Encrypt(encryptionKey)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	err = e.Sign(signingKey)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if bytes.Equal(e.Data, originalData) {
		t.Fatalf("Encrypt() did not change data")
	}

	// Tamper with data
	originalEncryptedData := bytes.Clone(e.Data)
	e.Data[0] ^= 0xff

	err = e.Decrypt(encryptionKey)
	if err == nil {
		t.Fatalf("Decrypt() did not return an error on tampered data")
	}
	e.Data = originalEncryptedData // restore

	err = e.Decrypt(encryptionKey)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if !bytes.Equal(e.Data, originalData) {
		t.Fatalf("data not restored after decryption, got %s, want %s", e.Data, originalData)
	}
}

func TestSignatureAndEncryption(t *testing.T) {
	signingKey := make([]byte, 32)
	_, err := rand.Read(signingKey)
	if err != nil {
		t.Fatalf("Failed to generate signing key: %v", err)
	}
	encryptionKey := make([]byte, 32)
	_, err = rand.Read(encryptionKey)
	if err != nil {
		t.Fatalf("Failed to generate encryption key: %v", err)
	}
	originalData := []byte("very secret data")

	e := New(bytes.Clone(originalData))

	// Encrypt first, then sign (so signature covers encrypted data)
	err = e.Encrypt(encryptionKey)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	err = e.Sign(signingKey)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Verify the signature while data is still encrypted
	err = e.Verify(signingKey)
	if err != nil {
		t.Fatalf("Verify() error = %v for a valid signature", err)
	}

	// Tamper with signature
	originalSig := make([]byte, len(e.Signature))
	copy(originalSig, e.Signature)
	e.Signature[0] ^= 0xff
	err = e.Verify(signingKey)
	if !errors.Is(err, ErrEnvelopeHasBeenTampered) {
		t.Fatalf("Verify() error = %v, want %v for an invalid signature", err, ErrEnvelopeHasBeenTampered)
	}

	// Restore signature for decryption test
	copy(e.Signature, originalSig)

	// Now decrypt
	err = e.Decrypt(encryptionKey)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if !bytes.Equal(e.Data, originalData) {
		t.Fatalf("data not restored after decryption, got %s, want %s", e.Data, originalData)
	}
}

func TestEnvelope_MarshalUnmarshalBinary(t *testing.T) {
	t.Run("SuccessfulRoundTrip", func(t *testing.T) {
		signingKey := make([]byte, 32)
		_, err := rand.Read(signingKey)
		if err != nil {
			t.Fatalf("Failed to generate signing key: %v", err)
		}
		encryptionKey := make([]byte, 32)
		_, err = rand.Read(encryptionKey)
		if err != nil {
			t.Fatalf("Failed to generate encryption key: %v", err)
		}

		original := New([]byte("some important data"))
		original.ID = []byte("test-id-123")
		original.Metadata = map[string]string{"origin": "test", "user": "alice"}
		original.TelemetryContext = map[string]string{"traceId": "abc-def"}
		if err := original.Sign(signingKey); err != nil {
			t.Fatalf("Failed to sign original envelope: %v", err)
		}
		if err := original.Encrypt(encryptionKey); err != nil {
			t.Fatalf("Failed to encrypt original envelope: %v", err)
		}

		// Marshal the original envelope
		binaryData, err := original.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary() error = %v, wantErr nil", err)
		}
		if len(binaryData) == 0 {
			t.Fatal("MarshalBinary() returned empty data")
		}

		// Unmarshal into a new envelope
		restored := &Envelope{}
		err = restored.UnmarshalBinary(binaryData)
		if err != nil {
			t.Fatalf("UnmarshalBinary() error = %v, wantErr nil", err)
		}

		// We can't use reflect.DeepEqual because the gob-encoded time might have
		// a monotonic clock component that differs. We compare fields manually.
		if original.Version != restored.Version {
			t.Errorf("Version mismatch: got %d, want %d", restored.Version, original.Version)
		}
		if !bytes.Equal(original.ID, restored.ID) {
			t.Errorf("ID mismatch: got %s, want %s", restored.ID, original.ID)
		}
		if !bytes.Equal(original.Data, restored.Data) {
			t.Errorf("Data mismatch: got %x, want %x", restored.Data, original.Data)
		}
		if !bytes.Equal(original.Signature, restored.Signature) {
			t.Errorf("Signature mismatch: got %x, want %x", restored.Signature, original.Signature)
		}
		if original.SecurityFlags != restored.SecurityFlags {
			t.Errorf("SecurityFlags mismatch: got %d, want %d", restored.SecurityFlags, original.SecurityFlags)
		}
		if !original.CreatedAt.Equal(restored.CreatedAt) {
			t.Errorf("CreatedAt mismatch: got %v, want %v", restored.CreatedAt, original.CreatedAt)
		}
		if !mapsEqual(original.Metadata, restored.Metadata) {
			t.Errorf("Metadata mismatch: got %v, want %v", restored.Metadata, original.Metadata)
		}
		if !mapsEqual(original.TelemetryContext, restored.TelemetryContext) {
			t.Errorf("TelemetryContext mismatch: got %v, want %v", restored.TelemetryContext, original.TelemetryContext)
		}
	})

	t.Run("UnmarshalInvalidData", func(t *testing.T) {
		invalidData := []byte("this is not a valid gob stream")
		e := &Envelope{}
		err := e.UnmarshalBinary(invalidData)
		if err == nil {
			t.Error("UnmarshalBinary() with invalid data should have returned an error, but got nil")
		}
	})
}

// mapsEqual checks if two string maps are equal.
func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || v != w {
			return false
		}
	}
	return true
}

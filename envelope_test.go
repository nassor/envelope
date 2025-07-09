package envelope

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

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
		if err := original.Seal(encryptionKey, signingKey); err != nil {
			t.Fatalf("Failed to seal original envelope: %v", err)
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
		restored := Empty()
		err = restored.UnmarshalBinary(binaryData)
		if err != nil {
			t.Fatalf("UnmarshalBinary() error = %v, wantErr nil", err)
		}

		// Before comparing, we need to unseal the restored envelope to check the data
		if err := restored.Unseal(encryptionKey, signingKey); err != nil {
			t.Fatalf("Failed to unseal restored envelope: %v", err)
		}

		// After unsealing, the encrypted data is replaced by the original data.
		// For comparison purposes, we need to re-encrypt the original data to match
		// what was in the marshaled data.
		// A simpler approach is to compare the fields that are not affected by encryption.
		// Let's reset the data and signature on the original for a moment to compare the rest.
		original.Data = restored.Data

		// We can't use reflect.DeepEqual because the gob-encoded time might have
		// a monotonic clock component that differs. We compare fields manually.
		if original.Version != restored.Version {
			t.Errorf("Version mismatch: got %d, want %d", restored.Version, original.Version)
		}
		if !bytes.Equal(original.ID, restored.ID) {
			t.Errorf("ID mismatch: got %s, want %s", restored.ID, original.ID)
		}
		// Data is compared after unsealing, so it should match the original plaintext
		if !bytes.Equal(restored.Data, []byte("some important data")) {
			t.Errorf("Data mismatch after unsealing: got %s, want %s", restored.Data, "some important data")
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

func TestSealUnseal(t *testing.T) {
	signingKey := make([]byte, 32)
	if _, err := rand.Read(signingKey); err != nil {
		t.Fatalf("Failed to generate signing key: %v", err)
	}
	encryptionKey := make([]byte, 32)
	if _, err := rand.Read(encryptionKey); err != nil {
		t.Fatalf("Failed to generate encryption key: %v", err)
	}
	originalData := []byte("very secret data for seal/unseal")

	t.Run("Sign and Encrypt", func(t *testing.T) {
		e := New(bytes.Clone(originalData))

		if err := e.Seal(encryptionKey, signingKey); err != nil {
			t.Fatalf("Seal() error = %v", err)
		}

		// Check that data is encrypted and signature is present
		if bytes.Equal(e.Data, originalData) {
			t.Fatal("Data was not encrypted after Seal()")
		}
		if len(e.Signature) == 0 {
			t.Fatal("Signature was not created after Seal()")
		}

		// Unseal should succeed
		if err := e.Unseal(encryptionKey, signingKey); err != nil {
			t.Fatalf("Unseal() error = %v", err)
		}

		// Check that data is restored
		if !bytes.Equal(e.Data, originalData) {
			t.Fatalf("data not restored after Unseal(), got %s, want %s", e.Data, originalData)
		}
	})

	t.Run("Tamper with Data", func(t *testing.T) {
		e := New(bytes.Clone(originalData))
		e.SecurityFlags = FlagSigned | FlagEncrypted
		if err := e.Seal(encryptionKey, signingKey); err != nil {
			t.Fatalf("Seal() error = %v", err)
		}

		// Tamper with the encrypted data
		e.Data[0] ^= 0xff

		// Unseal should fail
		err := e.Unseal(encryptionKey, signingKey)
		if err == nil {
			t.Fatal("Unseal() should have failed on tampered data, but it did not")
		}
	})

	t.Run("Tamper with Signature", func(t *testing.T) {
		e := New(bytes.Clone(originalData))
		e.SecurityFlags = FlagSigned | FlagEncrypted
		if err := e.Seal(encryptionKey, signingKey); err != nil {
			t.Fatalf("Seal() error = %v", err)
		}

		// Tamper with the signature
		e.Signature[0] ^= 0xff

		// Unseal should fail
		err := e.Unseal(encryptionKey, signingKey)
		if !errors.Is(err, ErrEnvelopeHasBeenTampered) {
			t.Fatalf("Unseal() with tampered signature returned wrong error, got %v, want %v", err, ErrEnvelopeHasBeenTampered)
		}
	})

	t.Run("Sign Only", func(t *testing.T) {
		e := New(bytes.Clone(originalData))
		e.SecurityFlags = FlagSigned

		if err := e.Seal(nil, signingKey); err != nil {
			t.Fatalf("Seal() with sign-only failed: %v", err)
		}

		// Data should not be encrypted
		if !bytes.Equal(e.Data, originalData) {
			t.Fatal("Data was encrypted in sign-only mode")
		}
		if len(e.Signature) == 0 {
			t.Fatal("Signature was not created in sign-only mode")
		}

		// Unseal should succeed
		if err := e.Unseal(nil, signingKey); err != nil {
			t.Fatalf("Unseal() with sign-only failed: %v", err)
		}
	})

	t.Run("Encrypt Only", func(t *testing.T) {
		e := New(bytes.Clone(originalData))
		e.SecurityFlags = FlagEncrypted

		if err := e.Seal(encryptionKey, nil); err != nil {
			t.Fatalf("Seal() with encrypt-only failed: %v", err)
		}

		// Data should be encrypted, signature should be empty
		if bytes.Equal(e.Data, originalData) {
			t.Fatal("Data was not encrypted in encrypt-only mode")
		}
		if len(e.Signature) != 0 {
			t.Fatal("Signature was created in encrypt-only mode")
		}

		// Unseal should succeed
		if err := e.Unseal(encryptionKey, nil); err != nil {
			t.Fatalf("Unseal() with encrypt-only failed: %v", err)
		}
		if !bytes.Equal(e.Data, originalData) {
			t.Fatalf("data not restored after Unseal(), got %s, want %s", e.Data, originalData)
		}
	})
}

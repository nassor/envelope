package envelope

import (
	"bytes"
	"crypto/rand"
	"errors"
	"maps"
	"testing"
)

func TestEnvelope_EncryptDecrypt(t *testing.T) {
	encryptionKey := make([]byte, 32)

	_, err := rand.Read(encryptionKey)
	if err != nil {
		t.Fatalf("Failed to generate encryption key: %v", err)
	}

	originalData := []byte("very secret data")

	t.Run("Encrypt and Decrypt", func(t *testing.T) {
		e := New(bytes.Clone(originalData))

		err := e.Encrypt(encryptionKey)
		if err != nil {
			t.Fatalf("Encrypt() error = %v, wantErr nil", err)
		}

		if bytes.Equal(e.Data, originalData) {
			t.Fatalf("Encrypt() data was not modified")
		}

		if e.SecurityFlags&FlagEncrypted == 0 {
			t.Fatalf("Encrypt() FlagEncrypted was not set")
		}

		err = e.Decrypt(encryptionKey)
		if err != nil {
			t.Fatalf("Decrypt() error = %v, wantErr nil", err)
		}

		if !bytes.Equal(e.Data, originalData) {
			t.Errorf("Decrypt() got %v, want %v", e.Data, originalData)
		}
	})

	t.Run("TamperAAD_ID", func(t *testing.T) {
		e := New(bytes.Clone(originalData))

		e.ID = []byte("test-id")

		err := e.Encrypt(encryptionKey)
		if err != nil {
			t.Fatalf("Encrypt() error = %v", err)
		}

		// Tamper with the ID, which is part of the AAD
		e.ID = []byte("tampered-id")

		err = e.Decrypt(encryptionKey)
		if err == nil {
			t.Fatal("Decrypt() did not return an error on tampered AAD (ID)")
		}

		if err.Error() != "cipher: message authentication failed" {
			t.Errorf("Decrypt() error = %v, want 'cipher: message authentication failed'", err)
		}
	})

	t.Run("TamperAAD_Metadata", func(t *testing.T) {
		e := New(bytes.Clone(originalData))

		e.Metadata["key"] = "value"

		err := e.Encrypt(encryptionKey)
		if err != nil {
			t.Fatalf("Encrypt() error = %v", err)
		}

		// Tamper with the Metadata, which is part of the AAD
		e.Metadata["key"] = "tampered-value"

		err = e.Decrypt(encryptionKey)
		if err == nil {
			t.Fatal("Decrypt() did not return an error on tampered AAD (Metadata)")
		}

		if err.Error() != "cipher: message authentication failed" {
			t.Errorf("Decrypt() error = %v, want 'cipher: message authentication failed'", err)
		}
	})

	t.Run("DecryptNotEncrypted", func(t *testing.T) {
		e := New(bytes.Clone(originalData))

		err := e.Decrypt(encryptionKey)
		if err != nil {
			t.Errorf("Decrypt() error = %v, wantErr nil", err)
		}

		if !bytes.Equal(e.Data, originalData) {
			t.Errorf("Decrypt() data was modified, got %v, want %v", e.Data, originalData)
		}
	})

	t.Run("DecryptTooShort", func(t *testing.T) {
		e := New([]byte("short"))

		e.SecurityFlags |= FlagEncrypted // Manually set for this test case

		err := e.Decrypt(encryptionKey)
		if !errors.Is(err, ErrCiphertextTooShort) {
			t.Errorf("Decrypt() error = %v, want %v", err, ErrCiphertextTooShort)
		}
	})

	t.Run("DecryptInvalidNonce", func(t *testing.T) {
		e := New(make([]byte, 24)) // AES-GCM nonce size is 12, so this is enough

		e.SecurityFlags |= FlagEncrypted // Manually set for this test case

		err := e.Decrypt(encryptionKey)
		if err == nil {
			t.Errorf("Decrypt() error = nil, wantErr")
		}
	})

	t.Run("EncryptLargeData", func(t *testing.T) {
		encryptionKey := make([]byte, 32)

		_, err := rand.Read(encryptionKey)
		if err != nil {
			t.Fatalf("Failed to generate encryption key: %v", err)
		}

		// Generate 4MB of random data
		const dataSize = 4*1024*1024 + 3 // 4MB + 3 bytes for nonce

		originalData := make([]byte, dataSize)

		_, err = rand.Read(originalData)
		if err != nil {
			t.Fatalf("Failed to generate random data: %v", err)
		}

		e := New(bytes.Clone(originalData))

		err = e.Encrypt(encryptionKey)
		if err != nil {
			t.Fatalf("Encrypt() error = %v, wantErr nil", err)
		}

		if bytes.Equal(e.Data, originalData) {
			t.Fatalf("Encrypt() data was not modified")
		}

		err = e.Decrypt(encryptionKey)
		if err != nil {
			t.Fatalf("Decrypt() error = %v, wantErr nil", err)
		}

		if !bytes.Equal(e.Data, originalData) {
			t.Errorf("Decrypt() got different data than original")
		}
	})
}

// Mock for testing error cases
type errorReader struct{}

func (r errorReader) Read(_ []byte) (n int, err error) {
	return 0, errors.New("forced error")
}

func TestEncryptionErrorCases(t *testing.T) {
	encryptionKey := make([]byte, 32)

	_, err := rand.Read(encryptionKey)
	if err != nil {
		t.Fatalf("Failed to generate encryption key: %v", err)
	}

	t.Run("EncryptRandError", func(t *testing.T) {
		originalRandReader := rand.Reader

		rand.Reader = errorReader{}

		defer func() { rand.Reader = originalRandReader }()

		e := New([]byte("test"))

		err := e.Encrypt(encryptionKey)
		if err == nil {
			t.Error("Encrypt() did not return error on rand.Reader failure")
		}

		if e.SecurityFlags&FlagEncrypted != 0 {
			t.Errorf("Encrypt() did not revert FlagEncrypted on error")
		}
	})
}

func TestWithNonceSize(t *testing.T) {
	originalData := []byte("very secret data")
	encryptionKey := make([]byte, 32)

	_, err := rand.Read(encryptionKey)
	if err != nil {
		t.Fatalf("Failed to generate encryption key: %v", err)
	}

	t.Run("CustomNonceSize", func(t *testing.T) {
		customNonceSize := 24
		e := New(bytes.Clone(originalData), WithNonceSize(customNonceSize))

		err := e.Encrypt(encryptionKey)
		if err != nil {
			t.Fatalf("Encrypt() with custom nonce size failed: %v", err)
		}

		// 16 is the GCM tag size
		expectedLen := customNonceSize + len(originalData) + 16
		if len(e.Data) != expectedLen {
			t.Errorf("Encrypted data length = %d, want %d", len(e.Data), expectedLen)
		}

		err = e.Decrypt(encryptionKey)
		if err != nil {
			t.Fatalf("Decrypt() with custom nonce size failed: %v", err)
		}

		if !bytes.Equal(e.Data, originalData) {
			t.Errorf("Decrypt() got %v, want %v", e.Data, originalData)
		}
	})

	t.Run("InvalidNonceSizeDefaults", func(t *testing.T) {
		e := New(bytes.Clone(originalData), WithNonceSize(0))

		err := e.Encrypt(encryptionKey)
		if err != nil {
			t.Fatalf("Encrypt() with invalid nonce size failed: %v", err)
		}

		// Should default to 12
		defaultNonceSize := 12

		expectedLen := defaultNonceSize + len(originalData) + 16
		if len(e.Data) != expectedLen {
			t.Errorf("Encrypted data length = %d, want %d", len(e.Data), expectedLen)
		}

		err = e.Decrypt(encryptionKey)
		if err != nil {
			t.Fatalf("Decrypt() with default nonce size failed: %v", err)
		}
	})

	t.Run("MismatchedNonceSize", func(t *testing.T) {
		// Encrypt with default nonce size
		e1 := New(bytes.Clone(originalData))

		err := e1.Encrypt(encryptionKey)
		if err != nil {
			t.Fatalf("Encrypt() failed: %v", err)
		}

		// Attempt to decrypt with a different nonce size
		e2 := New(nil, WithNonceSize(24))

		e2.Data = bytes.Clone(e1.Data)
		e2.SecurityFlags = e1.SecurityFlags

		err = e2.Decrypt(encryptionKey)
		// The error is "message authentication failed" because attempting to decrypt
		// with the wrong nonce size leads to an incorrect parsing of the nonce
		// and ciphertext, causing the authentication tag check to fail.
		if err == nil || err.Error() != "cipher: message authentication failed" {
			t.Errorf("Decrypt() with mismatched nonce size error = %v, want 'cipher: message authentication failed'", err)
		}
	})
}

func TestWithEncryptedTelemetry(t *testing.T) {
	encryptionKey := make([]byte, 32)
	if _, err := rand.Read(encryptionKey); err != nil {
		t.Fatalf("Failed to generate encryption key: %v", err)
	}

	originalData := []byte("some data")
	originalTelemetry := map[string]string{
		"traceID": "abc-123",
		"spanID":  "def-456",
	}

	t.Run("Enabled", func(t *testing.T) {
		e := New(bytes.Clone(originalData), WithEncryptedTelemetry())

		e.TelemetryContext = maps.Clone(originalTelemetry)

		err := e.Encrypt(encryptionKey)
		if err != nil {
			t.Fatalf("Encrypt() error = %v, wantErr nil", err)
		}

		// Check that telemetry values are encrypted (i.e., not the same as original)
		if e.TelemetryContext["traceID"] == originalTelemetry["traceID"] {
			t.Error("TelemetryContext[traceID] was not encrypted")
		}

		if e.TelemetryContext["spanID"] == originalTelemetry["spanID"] {
			t.Error("TelemetryContext[spanID] was not encrypted")
		}

		err = e.Decrypt(encryptionKey)
		if err != nil {
			t.Fatalf("Decrypt() error = %v, wantErr nil", err)
		}

		// Check that telemetry values are decrypted correctly
		if e.TelemetryContext["traceID"] != originalTelemetry["traceID"] {
			t.Errorf("Decrypted TelemetryContext[traceID] = %q, want %q", e.TelemetryContext["traceID"], originalTelemetry["traceID"])
		}

		if e.TelemetryContext["spanID"] != originalTelemetry["spanID"] {
			t.Errorf("Decrypted TelemetryContext[spanID] = %q, want %q", e.TelemetryContext["spanID"], originalTelemetry["spanID"])
		}
	})

	t.Run("Disabled", func(t *testing.T) {
		e := New(bytes.Clone(originalData)) // No WithEncryptTelemetry option

		e.TelemetryContext = maps.Clone(originalTelemetry)

		err := e.Encrypt(encryptionKey)
		if err != nil {
			t.Fatalf("Encrypt() error = %v, wantErr nil", err)
		}

		// Check that telemetry values are NOT encrypted
		if e.TelemetryContext["traceID"] != originalTelemetry["traceID"] {
			t.Errorf("TelemetryContext[traceID] was encrypted, but should not have been")
		}

		if e.TelemetryContext["spanID"] != originalTelemetry["spanID"] {
			t.Errorf("TelemetryContext[spanID] was encrypted, but should not have been")
		}

		err = e.Decrypt(encryptionKey)
		if err != nil {
			t.Fatalf("Decrypt() error = %v, wantErr nil", err)
		}

		// Check that telemetry values remain the same
		if e.TelemetryContext["traceID"] != originalTelemetry["traceID"] {
			t.Errorf("TelemetryContext[traceID] = %q, want %q", e.TelemetryContext["traceID"], originalTelemetry["traceID"])
		}

		if e.TelemetryContext["spanID"] != originalTelemetry["spanID"] {
			t.Errorf("TelemetryContext[spanID] = %q, want %q", e.TelemetryContext["spanID"], originalTelemetry["spanID"])
		}
	})

	t.Run("TamperedTelemetry", func(t *testing.T) {
		e := New(bytes.Clone(originalData), WithEncryptedTelemetry())

		e.TelemetryContext = maps.Clone(originalTelemetry)

		err := e.Encrypt(encryptionKey)
		if err != nil {
			t.Fatalf("Encrypt() error = %v", err)
		}

		// Tamper with one of the encrypted telemetry values
		e.TelemetryContext["traceID"] += "tamper"

		err = e.Decrypt(encryptionKey)
		if err == nil {
			t.Fatal("Decrypt() did not return an error on tampered telemetry")
		}

		if err.Error() != "cipher: message authentication failed" {
			t.Errorf("Decrypt() error = %v, want 'cipher: message authentication failed'", err)
		}
	})
}

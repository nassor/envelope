package envelope

import (
	"bytes"
	"crypto/rand"
	"errors"
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
		e := New(make([]byte, 24))       // AES-GCM nonce size is 12, so this is enough
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

func (r errorReader) Read(p []byte) (n int, err error) {
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

# Go Envelope

This project provides a secure, anti-tampering Go `Envelope` struct designed to wrap and protect data. It features optional HMAC signing and AES-GCM encryption, controlled by a simple bitmask.

## Features

* **HMAC Signing:** Protects against tampering by signing critical envelope fields (`Version`, `ID`, `Data`, `Metadata`, `TelemetryContext`, `CreatedAt`).
* **AES-GCM Encryption:** Encrypts the envelope's `Data` field for confidentiality.
* **Security Flags:** A bitmask (`FlagSigned`, `FlagEncrypted`) allows for easy configuration of security features.
* **Binary Serialization:** Efficient `MarshalBinary` and `UnmarshalBinary` methods using `encoding/gob` for fast serialization and deserialization.
* **Robust and Tested:** Includes a comprehensive suite of unit tests covering signing, verification, encryption, decryption, and serialization.

## Usage

### Creating a New Envelope

First, create a new `Envelope`:

```go
package main

import (
	"crypto/rand"
	"fmt"
	"log"

	"github.com/nassor/envelope"
)

func main() {
	// Create a key for signing and encryption (must be 32 bytes for AES-256)
	key := make([]byte, 32)
	// In a real application, use a secure key management system.
	if _, err := rand.Read(key); err != nil {
		log.Fatalf("Failed to create key: %v", err)
	}

	// Create a new envelope with some data
	originalData := []byte("this is a secret message")
	e := envelope.New(originalData, 0)
	e.ID = []byte("message-123")
	e.Metadata["sender"] = "alice"

	// Sign and encrypt the envelope
	if err := e.Sign(key); err != nil {
		log.Fatalf("Failed to sign envelope: %v", err)
	}
	if err := e.Encrypt(key); err != nil {
		log.Fatalf("Failed to encrypt envelope: %v", err)
	}

	fmt.Println("Envelope created, signed, and encrypted.")
}
```

### Verifying and Decrypting

To verify and decrypt the envelope, you would typically serialize it, send it over a network, and then deserialize it on the receiving end.

```go
// ... (previous code from creating an envelope)

// Serialize the envelope for transmission
binaryData, err := e.MarshalBinary()
if err != nil {
	log.Fatalf("Failed to marshal envelope: %v", err)
}

// --- On the receiving end ---

// Deserialize the data into a new envelope
receivedEnvelope := &envelope.Envelope{}
if err := receivedEnvelope.UnmarshalBinary(binaryData); err != nil {
	log.Fatalf("Failed to unmarshal envelope: %v", err)
}

// Decrypt the data first
if err := receivedEnvelope.Decrypt(key); err != nil {
	log.Fatalf("Failed to decrypt envelope: %v", err)
}

// Verify the signature to ensure it hasn't been tampered with
if err := receivedEnvelope.Verify(key); err != nil {
	log.Fatalf("Failed to verify envelope: %v", err)
}

fmt.Printf("Successfully verified and decrypted. Original message: %s\n", receivedEnvelope.Data)
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

# Envelope

This project provides a secure, anti-tampering Go `Envelope` struct designed to wrap and protect data. It features optional HMAC signing and AES-GCM encryption, controlled by a simple bitmask.

## Features

* **HMAC Signing:** Protects against tampering by signing envelope fields.
* **AES-GCM Encryption:** Encrypts the envelope's `Data` field for confidentiality.
* **Security Flags:** A bitmask allows for easy configuration of security features.
* **Separate Keys:** Uses distinct keys for signing and encryption operations for enhanced security.
* **Binary Serialization:** Efficient `MarshalBinary` and `UnmarshalBinary` methods for fast serialization and deserialization.
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
    // Create separate keys for signing and encryption (both must be 32 bytes)
    signingKey := make([]byte, 32)
    encryptionKey := make([]byte, 32)
    // In a real application, use a secure key management system.
    if _, err := rand.Read(signingKey); err != nil {
        log.Fatalf("Failed to create signing key: %v", err)
    }
    if _, err := rand.Read(encryptionKey); err != nil {
        log.Fatalf("Failed to create encryption key: %v", err)
    }

    // Create a new envelope with some data
    originalData := []byte("this is a secret message")
    e := envelope.New(originalData)
    e.ID = []byte("message-123")
    e.Metadata["sender"] = "alice"

    // Encrypt first, then sign (signature covers the encrypted data)
    if err := e.Encrypt(encryptionKey); err != nil {
        log.Fatalf("Failed to encrypt envelope: %v", err)
    }
    if err := e.Sign(signingKey); err != nil {
        log.Fatalf("Failed to sign envelope: %v", err)
    }

    fmt.Println("Envelope created, encrypted, and signed.")
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

// Verify the signature first (while data is still encrypted)
if err := receivedEnvelope.Verify(signingKey); err != nil {
    log.Fatalf("Failed to verify envelope: %v", err)
}

// Then decrypt the data using the encryption key
if err := receivedEnvelope.Decrypt(encryptionKey); err != nil {
    log.Fatalf("Failed to decrypt envelope: %v", err)
}

fmt.Printf("Successfully verified and decrypted. Original message: %s\n", receivedEnvelope.Data)
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

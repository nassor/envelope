# Envelope

This project provides a secure, anti-tampering Go `Envelope` struct designed to wrap and protect data. It features optional HMAC signing and AES-GCM encryption, controlled by a simple bitmask.

## Features

* **HMAC Signing:** Protects against tampering by signing envelope fields.
* **AES-GCM Encryption:** Encrypts the envelope's `Data` field for confidentiality.
* **Time-based Expiration:** An optional `ExpiresAt` field helps prevent replay attacks.
* **Security Flags:** A bitmask allows for easy configuration of security features.
* **Separate Keys:** Uses distinct keys for signing and encryption operations for enhanced security.
* **Canonical Serialization:** Uses CBOR with canonical ordering to ensure consistent signature verification.
* **Customizable Crypto:** Allows configuration of the HMAC hash function and AES-GCM nonce size.
* **Robust and Tested:** Includes a comprehensive suite of unit tests.

## Usage

The primary workflow involves creating an envelope, sealing it, and then transmitting it. The receiver then unseals the envelope to access the data securely.

### 1. Creating and Sealing an Envelope (Sender)

This example demonstrates the simplest case: creating an envelope with data, sealing it for both encryption and signing, and then serializing it to a byte slice for transmission.

```go
package main

import (
    "crypto/rand"
    "fmt"
    "log"
    "time"

    "github.com/nassor/envelope"
)

func main() {
    // 1. Generate cryptographic keys.
    // In a real application, use a secure key management system.
    signingKey := make([]byte, 32)
    encryptionKey := make([]byte, 32)
    if _, err := rand.Read(signingKey); err != nil {
        log.Fatalf("Failed to create signing key: %v", err)
    }
    if _, err := rand.Read(encryptionKey); err != nil {
        log.Fatalf("Failed to create encryption key: %v", err)
    }

    // 2. Create a new envelope with the data to protect.
    e := envelope.New([]byte("this is a secret message"))

    // 3. Populate the envelope's other fields.
    e.ID = []byte("message-123")
    e.Metadata = map[string]string{"sender": "alice"}
    e.ExpiresAt = time.Now().Add(5 * time.Minute) // Set an expiration time
    e.SecurityFlags = envelope.FlagEncrypted | envelope.FlagSigned

    // 4. Seal the envelope to apply encryption and signing.
    if err := e.Seal(encryptionKey, signingKey); err != nil {
        log.Fatalf("Failed to seal envelope: %v", err)
    }

    // 5. Marshal the sealed envelope into a binary format for transmission.
    binaryData, err := e.MarshalBinary()
    if err != nil {
        log.Fatalf("Failed to marshal envelope: %v", err)
    }

    fmt.Println("Envelope sealed and marshaled successfully.")
    // In a real application, you would send the binaryData to the receiver.
    // For this example, we'll pass it to a simulated receiver function.
    receiveAndProcess(binaryData, signingKey, encryptionKey)
}
```

### 2. Unsealing an Envelope (Receiver)

The receiver unmarshals the binary data and then unseals the envelope using the same keys. The `Unseal` method automatically checks the expiration time.

```go
func receiveAndProcess(binaryData []byte, signingKey, encryptionKey []byte) {
    // 1. Create a new, empty envelope to hold the received data.
    receivedEnvelope := envelope.Empty()

    // 2. Unmarshal the binary data into the envelope.
    if err := receivedEnvelope.UnmarshalBinary(binaryData); err != nil {
        log.Fatalf("Failed to unmarshal envelope: %v", err)
    }

    // 3. Unseal the envelope to verify its signature and decrypt its data.
    // This will fail if the signature is invalid or the envelope has expired.
    if err := receivedEnvelope.Unseal(encryptionKey, signingKey); err != nil {
        log.Fatalf("Failed to unseal envelope: %v", err)
    }

    fmt.Printf("Successfully unsealed. Original message: %s\n", receivedEnvelope.Data)
}
```

## Time-based Expiration (Replay Protection)

The `ExpiresAt` field (`time.Time`) can be set to prevent replay attacks. When an envelope is signed, the `ExpiresAt` value is included in the HMAC computation. The `Unseal` and `Verify` methods automatically check if the current time is past `ExpiresAt`. If the envelope has expired, an error is returned.

To use this feature, simply set the `ExpiresAt` field on the envelope before sealing or signing:

```go
e.ExpiresAt = time.Now().Add(5 * time.Minute)
```

If you do not wish to use this feature, leave the `ExpiresAt` field as its zero value. The verification logic will ignore it.

## Customization with Options

You can customize the envelope's cryptographic functions during creation. **It is critical that the sender and receiver use the exact same options.**

### `WithHMACHash`

This option changes the hash algorithm used for the HMAC signature. The default is `sha3.New384`.

**Sender:**

```go
import "crypto/sha256"
// ...
e := envelope.New(data, envelope.WithHMACHash(sha256.New))
// ... seal and marshal
```

**Receiver:**

```go
import "crypto/sha256"
// ...
receivedEnvelope := envelope.Empty(envelope.WithHMACHash(sha256.New))
// ... unmarshal and unseal
```

### `WithNonceSize`

This option changes the nonce size for AES-GCM encryption. The default is 12 bytes, which is the standard and recommended size. Only change this if you have a specific requirement and understand the security implications of using a non-standard nonce size.

**Sender:**

```go
// Use a 24-byte nonce
e := envelope.New(data, envelope.WithNonceSize(24))
// ... seal and marshal
```

**Receiver:**

```go
// Must also use a 24-byte nonce
receivedEnvelope := envelope.Empty(envelope.WithNonceSize(24))
// ... unmarshal and unseal
```

### `WithEncryptedTelemetry`

This option enables encryption for the `TelemetryContext` map. By default, this map is not encrypted. When this option is used, each value in the `TelemetryContext` map is individually encrypted using AES-GCM, similar to the main `Data` field. This is useful for protecting potentially sensitive context information while still allowing other metadata to be inspected.

**Sender:**

```go
// Encrypt the TelemetryContext along with the data
e := envelope.New(data, envelope.WithEncryptedTelemetry())
e.TelemetryContext = map[string]string{"traceID": "trace-xyz-789"}
// ... seal and marshal
```

**Receiver:**

```go
// The receiver must also specify the option to correctly decrypt the telemetry
receivedEnvelope := envelope.Empty(envelope.WithEncryptedTelemetry())
// ... unmarshal and unseal
```

## Granular Control: Signing and Encryption

While `Seal()` and `Unseal()` are convenient for the common case of applying both signing and encryption, you can also apply these protections individually. This is useful when you only need to ensure data integrity (`Sign`/`Verify`) or only need to ensure confidentiality (`Encrypt`/`Decrypt`).

### Signing Only: Ensuring Data Integrity

If you only need to protect an envelope against tampering, you can use the `Sign()` and `Verify()` methods. The data remains in plaintext but is protected by an HMAC signature.

**Sender (Signing):**

```go
// 1. Create an envelope.
e := envelope.New([]byte("This message is not secret, but it must not be changed."))
e.Metadata = map[string]string{"source": "audit-log"}
e.ExpiresAt = time.Now().Add(1 * time.Hour)

// 2. Sign the envelope.
// The FlagSigned is automatically set by the Sign() method.
if err := e.Sign(signingKey); err != nil {
    log.Fatalf("Failed to sign envelope: %v", err)
}

// 3. Marshal for transmission.
binaryData, err := e.MarshalBinary()
// ... send binaryData
```

**Receiver (Verifying):**

```go
// 1. Unmarshal the received data.
receivedEnvelope := envelope.Empty()
if err := receivedEnvelope.UnmarshalBinary(binaryData); err != nil {
    log.Fatalf("Failed to unmarshal envelope: %v", err)
}

// 2. Verify the signature. This also checks the expiration time.
if err := receivedEnvelope.Verify(signingKey); err != nil {
    log.Fatalf("Envelope verification failed, data may have been tampered with: %v", err)
}

fmt.Printf("Verified message: %s\n", receivedEnvelope.Data)
```

### Encryption Only: Ensuring Confidentiality

If you only need to keep the envelope's data confidential, you can use the `Encrypt()` and `Decrypt()` methods. The envelope's metadata remains visible, but the `Data` field is encrypted. Note that without a signature, an attacker could potentially tamper with the unencrypted fields (`ID`, `Metadata`, etc.).

**Sender (Encrypting):**

```go
// 1. Create an envelope.
e := envelope.New([]byte("This is a top secret message."))
e.ID = []byte("secret-message-456")

// 2. Encrypt the envelope's data.
// The FlagEncrypted is automatically set by the Encrypt() method.
if err := e.Encrypt(encryptionKey); err != nil {
    log.Fatalf("Failed to encrypt envelope: %v", err)
}

// 3. Marshal for transmission.
binaryData, err := e.MarshalBinary()
// ... send binaryData
```

**Receiver (Decrypting):**

```go
// 1. Unmarshal the received data.
receivedEnvelope := envelope.Empty()
if err := receivedEnvelope.UnmarshalBinary(binaryData); err != nil {
    log.Fatalf("Failed to unmarshal envelope: %v", err)
}

// 2. Decrypt the data.
if err := receivedEnvelope.Decrypt(encryptionKey); err != nil {
    log.Fatalf("Failed to decrypt envelope: %v", err)
}

fmt.Printf("Decrypted secret: %s\n", receivedEnvelope.Data)
```

## Security Considerations

### Key Management

This library does not handle key management. You are responsible for generating, storing, and distributing keys securely. Using a dedicated key management system (KMS) or a hardware security module (HSM) is highly recommended for production applications. **Never hardcode keys in your source code.**

### Integrity of Metadata (Authenticated Associated Data)

When an envelope is signed, all of its fields (`ID`, `Metadata`, `ExpiresAt`, `SecurityFlags`, `Data` or `Ciphertext`) are included in the HMAC calculation. This ensures the integrity of the entire envelope.

When using encryption (`FlagEncrypted`), the signature is calculated over the ciphertext, not the plaintext data. The encryption itself (AES-GCM) binds the ciphertext to the unencrypted metadata fields (`ID`, `Metadata`, `ExpiresAt`) by using them as Authenticated Associated Data (AAD). This prevents an attacker from detaching the ciphertext and reattaching it to a different envelope with different metadata.

For these reasons, it is highly recommended to always use the `FlagSigned` flag, even when encrypting data, to ensure the full envelope is protected from tampering.

### Nonce Management

The `Encrypt` method generates a random nonce for each encryption operation. The nonce is prepended to the ciphertext. AES-GCM security relies on the uniqueness of the (key, nonce) pair. Reusing a nonce with the same key can lead to a catastrophic failure of confidentiality. By generating a sufficiently large random nonce for every encryption, the probability of reuse is negligible.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## ChaCha20 💃

### Overview

This repository hosts an implementation of the ChaCha20 stream cipher, and Poly1305 message authentication code as per [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439). These cryptographic algorithms offer robust solutions for ensuring data confidentiality, integrity, and authenticity.

### ChaCha20

ChaCha20 is a modern stream cipher known for its speed and security. It is designed to provide strong encryption and has become a popular choice in various cryptographic protocols, such as TLS and secure messaging applications.

#### Key Features:
- **High Speed**: Excels in software implementations, especially on platforms without specialized hardware support for cryptography.
- **Security**: Designed to be secure against a wide range of cryptographic attacks.
- **Flexibility**: Easily adaptable for both large data encryption and real-time data streaming.

#### Best Practices:
- Ensure unique nonces for each encryption operation.
- Securely manage and store encryption keys.

### Poly1305

Poly1305 is a fast and secure message authentication code (MAC) that works in conjunction with a cipher like ChaCha20. It provides a strong level of assurance against message tampering.

#### Key Features:
- **Efficiency**: Exceptionally fast, making it suitable for high-throughput applications.
- **Security**: Offers strong guarantees of authenticity.
- **One-Time Key Usage**: Each key must only be used once to maintain security.

#### Best Practices:
- Never reuse a key; always generate a new key for each message.
- Combine with a secure cipher like ChaCha20 for complete data protection.

### ChaCha20-Poly1305 AEAD

ChaCha20-Poly1305 AEAD combines the strengths of ChaCha20 and Poly1305, encrypting and authenticating data in a single step. It's recommended for scenarios where both confidentiality and integrity are crucial.

#### Key Features:
- **Authenticated Encryption**: Simultaneously encrypts and authenticates data.
- **Nonce-Misuse Resistance**: Provides security even if nonces are reused (though nonce reuse is not recommended).
- **Efficient**: Leverages the performance benefits of ChaCha20 and Poly1305.

#### Best Practices:
- Avoid nonce reuse to ensure the highest level of security.
- Verify the authenticity of decrypted data before using it.

## Background and History

### ChaCha20

Developed by Daniel J. Bernstein, ChaCha20 is an evolution of the earlier Salsa20 cipher. It was designed to provide strong cryptographic security while being highly efficient in software implementations.

### Poly1305

Also developed by Daniel J. Bernstein, Poly1305 provides a way to authenticate messages securely and is often used in combination with ciphers like ChaCha20.

### RFC 8439

RFC 8439 standardizes the algorithms and provides comprehensive guidelines for their implementation and use, ensuring consistency and security across different applications.

## Benchmarks

### Performance

Benchmarks were conducted on a MacBook Pro with the following specifications:
- **Chip**: Apple M2 Max
- **Memory**: 32GB

The benchmarks were performed by processing 1,000,000 bytes in each of 10 runs for each operation. The runtimes and throughput are as follows:

| Operation           | Runtime (µs)        | Throughput (MB/s) |
|---------------------|---------------------|-------------------|
| chacha20-poly1305   | 5884.89             | 169.93            |
| chacha20            | 4206.36             | 237.74            |
| poly1305            | 1405.16             | 711.66            |

These results highlight the high efficiency of the algorithms, making them ideal for high-throughput applications.

## Usage Examples

### Real-World Use Case: Secure Data Encryption/Decryption

**Scenario**: Encrypting and decrypting sensitive data using ChaCha20.

```dart
import 'dart:typed_data';
import 'package:chacha/export.dart';

Uint8List encrypt({
  required Uint8List plaintext,
  required Uint8List key,
  required Uint8List nonce,
}) {
  final ChaCha20 chacha20 = ChaCha20(key: key, nonce: nonce);
  return chacha20.convert(plaintext);
}

Uint8List decrypt({
  required Uint8List ciphertext,
  required Uint8List key,
  required Uint8List nonce,
}) {
  final ChaCha20 chacha20 = ChaCha20(key: key, nonce: nonce);
  return chacha20.convert(ciphertext);
}
```

### Real-World Use Case: Secure Data Encryption/Decryption Stream

**Scenario**: Encrypting and decrypting sensitive data using ChaCha20 streaming.

```dart
import 'dart:typed_data';
import 'package:chacha/export.dart';

Stream<List<int>> encrypt({
  required Stream<Uint8List> plaintext,
  required Uint8List key,
  required Uint8List nonce,
}) {
  final ChaCha20 chacha20 = ChaCha20(key: key, nonce: nonce);
  return plaintext.transform(chacha20);
}

Stream<List<int>> decrypt({
  required Stream<Uint8List> ciphertext,
  required Uint8List key,
  required Uint8List nonce,
}) {
  final ChaCha20 chacha20 = ChaCha20(key: key, nonce: nonce);
  return ciphertext.transform(chacha20);
}
```

### Real-World Use Case: Secure File Encryption/Decryption Stream

**Scenario**: Encrypting and decrypting sensitive files using ChaCha20 streaming.

```dart
import 'dart:typed_data';
import 'package:chacha/export.dart';

void process({
  required File inputFile,
  required File outputFile,
  required Uint8List key,
  required Uint8List nonce,
}) {
  final ChaCha20 chacha20 = ChaCha20(key: key, nonce: nonce);
  inputFile.openRead().transform(chacha20).pipe(outputFile.openWrite());
}
```

### Real-World Use Case: Data Authentication

**Scenario**: Generating a MAC for a message using Poly1305.

```dart
import 'dart:typed_data';
import 'package:chacha/poly1305.dart';

Uint8List authenticateMessage({
  required Uint8List message,
  required Uint8List key,
}) {
  Poly1305 poly1305 = Poly1305(key: key)
  Uint8List tag = poly1305.convert(message);
  // Use the tag for message verification
}
```

## Contribution

Contributions to improve the implementation, enhance security, and extend functionality are welcome. If you find any issues or have suggestions, please feel free to open an issue or submit a pull request.

import 'dart:convert';
import 'dart:typed_data';

import 'package:chacha/src/chacha20.dart';
import 'package:chacha/src/poly1305.dart';

/// ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD) (RFC 8439).
///
/// Combines the symmetric ChaCha20 cipher and Poly1305 MAC to provide encryption along with data integrity
/// and authenticity verification. This class is ideal for high-security scenarios, ensuring confidentiality,
/// integrity, and authenticity in encryption and authentication processes.
class ChaCha20Poly1305 extends Converter<List<int>, List<int>> {
  const ChaCha20Poly1305._(this._aad, this._chacha20, this._poly1305, this._encrypt);

  /// Converts and authenticates data using ChaCha20-Poly1305 AEAD scheme as per RFC 8439.
  ///
  /// Accepts a 256-bit key and a 96-bit nonce, data, and optional additional authenticated data (AAD).
  factory ChaCha20Poly1305(Uint8List? aad, Uint8List key, Uint8List nonce, bool encrypt) {
    if (key.length != 32) throw ArgumentError('Invalid key');
    if (nonce.length != 12) throw ArgumentError('Invalid nonce');

    return ChaCha20Poly1305._(
      aad ?? Uint8List(0),
      ChaCha20(key, nonce, 1),
      Poly1305(generateKey(key, nonce)),
      encrypt,
    );
  }

  final bool _encrypt;
  final Uint8List _aad;
  final ChaCha20 _chacha20;
  final Poly1305 _poly1305;

  @override
  Uint8List convert(List<int> input) {
    final int len = input.length;
    if (_encrypt && len < 16) throw Exception('Invalid data length.');
    final Uint8List buffer = Uint8List(_encrypt ? len + 16 : len - 16);

    final Uint8List cipher = _encrypt
        ? Uint8List.sublistView(buffer..setAll(0, _chacha20.convert(input)), 0, len)
        : Uint8List.sublistView(buffer..setRange(0, len - 16, input), 0, len - 16);

    final Uint8List mac = _poly1305.convert(_buildMacData(_aad, cipher));
    if (_encrypt) return buffer..setAll(len, mac);

    final List<int> tag = input.sublist(len - 16);
    if (!verifyMac(mac, tag)) throw Exception('MAC verification failed.');
    return _chacha20.convert(buffer);
  }

  /// Generates a Poly1305 key using the ChaCha20 block function with a zero counter as per RFC 8439.
  ///
  /// Accepts a 256-bit key and a 96-bit nonce.
  static Uint8List generateKey(Uint8List key, Uint8List nonce) {
    final Uint8List keystream = Uint8List(64);
    final Uint32List state = initState(key.buffer.asUint32List(), nonce.buffer.asUint32List());
    chacha20Block(0, keystream, state, Uint32List(16));
    return keystream.sublist(0, 32);
  }

  /// Verifies the integrity and authenticity of a message using its Poly1305 MAC.
  ///
  /// Accepts the key used to generate the MAC, the message, and the MAC to be verified.
  /// Use this to prevent timing attacks during MAC verification.
  static bool verifyMac(List<int> m1, List<int> m2) {
    if (m1.length != m2.length) return false;
    int result = 0;
    for (int i = 0; i < m1.length; i++) {
      result |= (m1[i] ^ m2[i]);
    }
    return result == 0;
  }

  static Uint8List _buildMacData(Uint8List aad, Uint8List bytes) {
    final int aadPaddedLen = (aad.length + 15) & ~15;
    final int bytePaddedLen = (bytes.length + 15) & ~15;
    final int paddedLen = aadPaddedLen + bytePaddedLen;
    return Uint8List(paddedLen + 16)
      ..setAll(0, aad)
      ..setAll(aadPaddedLen, bytes)
      ..buffer.asByteData(paddedLen).setUint64(0, aad.length, Endian.little)
      ..buffer.asByteData(paddedLen).setUint64(8, bytes.length, Endian.little);
  }
}

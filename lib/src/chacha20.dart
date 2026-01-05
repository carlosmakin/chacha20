import 'dart:convert';
import 'dart:typed_data';

import 'package:chacha/src/utilities.dart';

/// ChaCha20 Stream Cipher (RFC 8439).
///
/// A symmetric key cipher offering high performance with 256-bit keys and a
/// 96-bit nonce. ChaCha20 provides fast, secure encryption and decryption
/// operations, featuring optional counter-based operation for varied
/// cryptographic uses, particularly effective in streaming data encryption.
final class ChaCha20 extends Converter<List<int>, List<int>> {
  final Uint32List _state;
  final Uint8List _keystream;

  int w00 = 00, w01 = 00, w02 = 00, w03 = 00;
  int w04 = 00, w05 = 00, w06 = 00, w07 = 00;
  int w08 = 00, w09 = 00, w10 = 00, w11 = 00;
  int w12 = 00, w13 = 00, w14 = 00, w15 = 00;

  ChaCha20._(this._state, this._keystream);

  /// Converts data using ChaCha20 as per RFC 8439.
  ///
  /// Accepts a 256-bit key, 96-bit nonce, and an optional counter (default: 1).
  factory ChaCha20({
    required Uint8List key,
    required Uint8List nonce,
    int counter = 1,
  }) {
    if (key.length != 32) throw ArgumentError('Invalid key');
    if (nonce.length != 12) throw ArgumentError('Invalid nonce');

    final Uint32List state = Uint32List(32);
    state[00] = 0x61707865;
    state[01] = 0x3320646e;
    state[02] = 0x79622d32;
    state[03] = 0x6b206574;
    state[12] = counter;
    state.setAll(04, key.buffer.asUint32List());
    state.setAll(13, nonce.buffer.asUint32List());

    if (Endian.host != Endian.little) {
      final ByteData byteData = state.buffer.asByteData();
      for (int i = 0; i < 32; ++i) {
        state[i] = byteData.getUint32(i * 4, Endian.little);
      }
    }

    return ChaCha20._(state, state.buffer.asUint8List(64));
  }

  @override
  Uint8List convert(covariant Uint8List input) {
    final Uint8List output = Uint8List.fromList(input);

    final int blocks = input.length & ~63;
    for (int j = 0; j < blocks; ++_state[12]) {
      _chacha20BlockRounds();
      for (int i = 0; i < 64; ++i, ++j) {
        output[j] ^= _keystream[i];
      }
    }

    final int remaining = input.length % 64;
    if (remaining != 0) {
      _chacha20BlockRounds();
      for (int i = 0; i < remaining; ++i) {
        output[blocks + i] ^= _keystream[i];
      }
    }

    return output;
  }

  @override
  ByteConversionSink startChunkedConversion(Sink<List<int>> sink) {
    if (sink is! ByteConversionSink) sink = ByteConversionSink.from(sink);
    return _ChaCha20Sink(this, sink);
  }

  /// The ChaCha20 block function is the core of the ChaCha20 algorithm.
  Uint8List chacha20Block() {
    _chacha20BlockRounds();
    return _keystream.asUnmodifiableView();
  }

  /// Performs the core rounds of the ChaCha20 block cipher.
  void _chacha20BlockRounds() {
    w00 = _state[00];
    w01 = _state[01];
    w02 = _state[02];
    w03 = _state[03];
    w04 = _state[04];
    w05 = _state[05];
    w06 = _state[06];
    w07 = _state[07];
    w08 = _state[08];
    w09 = _state[09];
    w10 = _state[10];
    w11 = _state[11];
    w12 = _state[12];
    w13 = _state[13];
    w14 = _state[14];
    w15 = _state[15];

    for (int i = 0; i < 10; ++i) {
      /* Column rounds */

      // Quarter round on (0, 4, 8, 12)
      w00 = mask32 & (w00 + w04);
      w12 = rotl16(w12 ^ w00);
      w08 = mask32 & (w08 + w12);
      w04 = rotl12(w04 ^ w08);
      w00 = mask32 & (w00 + w04);
      w12 = rotl08(w12 ^ w00);
      w08 = mask32 & (w08 + w12);
      w04 = rotl07(w04 ^ w08);

      // Quarter round on (1, 5, 9, 13)
      w01 = mask32 & (w01 + w05);
      w13 = rotl16(w13 ^ w01);
      w09 = mask32 & (w09 + w13);
      w05 = rotl12(w05 ^ w09);
      w01 = mask32 & (w01 + w05);
      w13 = rotl08(w13 ^ w01);
      w09 = mask32 & (w09 + w13);
      w05 = rotl07(w05 ^ w09);

      // Quarter round on (2, 6, 10, 14)
      w02 = mask32 & (w02 + w06);
      w14 = rotl16(w14 ^ w02);
      w10 = mask32 & (w10 + w14);
      w06 = rotl12(w06 ^ w10);
      w02 = mask32 & (w02 + w06);
      w14 = rotl08(w14 ^ w02);
      w10 = mask32 & (w10 + w14);
      w06 = rotl07(w06 ^ w10);

      // Quarter round on (3, 7, 11, 15)
      w03 = mask32 & (w03 + w07);
      w15 = rotl16(w15 ^ w03);
      w11 = mask32 & (w11 + w15);
      w07 = rotl12(w07 ^ w11);
      w03 = mask32 & (w03 + w07);
      w15 = rotl08(w15 ^ w03);
      w11 = mask32 & (w11 + w15);
      w07 = rotl07(w07 ^ w11);

      /* Diagonal rounds */

      // Quarter round on (0, 5, 10, 15)
      w00 = mask32 & (w00 + w05);
      w15 = rotl16(w15 ^ w00);
      w10 = mask32 & (w10 + w15);
      w05 = rotl12(w05 ^ w10);
      w00 = mask32 & (w00 + w05);
      w15 = rotl08(w15 ^ w00);
      w10 = mask32 & (w10 + w15);
      w05 = rotl07(w05 ^ w10);

      // Quarter round on (1, 6, 11, 12)
      w01 = mask32 & (w01 + w06);
      w12 = rotl16(w12 ^ w01);
      w11 = mask32 & (w11 + w12);
      w06 = rotl12(w06 ^ w11);
      w01 = mask32 & (w01 + w06);
      w12 = rotl08(w12 ^ w01);
      w11 = mask32 & (w11 + w12);
      w06 = rotl07(w06 ^ w11);

      // Quarter round on (2, 7, 8, 13)
      w02 = mask32 & (w02 + w07);
      w13 = rotl16(w13 ^ w02);
      w08 = mask32 & (w08 + w13);
      w07 = rotl12(w07 ^ w08);
      w02 = mask32 & (w02 + w07);
      w13 = rotl08(w13 ^ w02);
      w08 = mask32 & (w08 + w13);
      w07 = rotl07(w07 ^ w08);

      // Quarter round on (3, 4, 9, 14)
      w03 = mask32 & (w03 + w04);
      w14 = rotl16(w14 ^ w03);
      w09 = mask32 & (w09 + w14);
      w04 = rotl12(w04 ^ w09);
      w03 = mask32 & (w03 + w04);
      w14 = rotl08(w14 ^ w03);
      w09 = mask32 & (w09 + w14);
      w04 = rotl07(w04 ^ w09);
    }

    // Save local variables back to working state.
    _state[16] = w00 + _state[00];
    _state[17] = w01 + _state[01];
    _state[18] = w02 + _state[02];
    _state[19] = w03 + _state[03];
    _state[20] = w04 + _state[04];
    _state[21] = w05 + _state[05];
    _state[22] = w06 + _state[06];
    _state[23] = w07 + _state[07];
    _state[24] = w08 + _state[08];
    _state[25] = w09 + _state[09];
    _state[26] = w10 + _state[10];
    _state[27] = w11 + _state[11];
    _state[28] = w12 + _state[12];
    _state[29] = w13 + _state[13];
    _state[30] = w14 + _state[14];
    _state[31] = w15 + _state[15];
  }

  /// Securely clears the internal state from memory.
  void close() {
    w00 = w01 = w02 = w03 = 00;
    w04 = w05 = w06 = w07 = 00;
    w08 = w09 = w10 = w11 = 00;
    w12 = w13 = w14 = w15 = 00;
    _state.fillRange(0, 32, 0);
  }
}

final class _ChaCha20Sink implements ByteConversionSink {
  const _ChaCha20Sink(this._converter, this._outputSink);

  final ChaCha20 _converter;
  final ByteConversionSink _outputSink;

  @override
  void add(covariant Uint8List chunk) {
    _outputSink.add(_converter.convert(chunk));
  }

  @override
  void addSlice(covariant Uint8List chunk, int start, int end, bool isLast) {
    add(Uint8List.sublistView(chunk, start, end));
    if (isLast) close();
  }

  @override
  void close() {
    _converter.close();
    _outputSink.close();
  }
}

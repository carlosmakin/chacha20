import 'dart:convert';
import 'dart:typed_data';

/// ChaCha20 Stream Cipher (RFC 8439).
///
/// A symmetric key cipher offering high performance with 256-bit keys and a 96-bit nonce. ChaCha20
/// provides fast, secure encryption and decryption operations, featuring optional counter-based operation
/// for varied cryptographic uses, particularly effective in streaming data encryption.
class ChaCha20 extends Converter<List<int>, List<int>> {
  final Uint32List _state;
  final Uint8List _keystream;

  const ChaCha20._(this._state, this._keystream);

  /// Converts data using ChaCha20 as per RFC 8439.
  ///
  /// Accepts a 256-bit key, a 96-bit nonce, and an optional counter (default: 1).
  factory ChaCha20(Uint8List key, Uint8List nonce, [int counter = 1]) {
    if (key.length != 32) throw ArgumentError('Invalid key');
    if (nonce.length != 12) throw ArgumentError('Invalid nonce');

    // Initializes the state with the constants, key, and nonce.
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
      for (int i = 0; i < 32; i++) {
        state[i] = byteData.getUint32(i * 4, Endian.little);
      }
    }

    return ChaCha20._(state, state.buffer.asUint8List(64));
  }

  @override
  Uint8List convert(List<int> input) {
    final Uint8List output = Uint8List.fromList(input);

    // Process all 64-byte chunks.
    final int block = input.length & ~63;
    for (int j = 0; j < block; ++_state[12]) {
      _chacha20BlockRounds();
      for (int i = 0; i < 64; i += 4, j += 4) {
        output[j] ^= _keystream[i];
        output[j + 01] ^= _keystream[i + 01];
        output[j + 02] ^= _keystream[i + 02];
        output[j + 03] ^= _keystream[i + 03];
      }
    }

    // Process any remaining bytes.
    final int remaining = input.length % 64;
    if (remaining != 0) {
      _chacha20BlockRounds();
      for (int i = 0; i < remaining; ++i) {
        output[block + i] ^= _keystream[i];
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
    return Uint8List.fromList(_keystream);
  }

  /// Performs the core rounds of the ChaCha20 block cipher.
  void _chacha20BlockRounds() {
    // Bit mask
    const int mask32 = 0xFFFFFFFF;

    // Rotates the left bits of a 32-bit unsigned integer.
    int rotl16(int value) => mask32 & value << 16 | value >> 16;
    int rotl12(int value) => mask32 & value << 12 | value >> 20;
    int rotl08(int value) => mask32 & value << 08 | value >> 24;
    int rotl07(int value) => mask32 & value << 07 | value >> 25;

    int ws00 = _state[00], ws01 = _state[01], ws02 = _state[02], ws03 = _state[03];
    int ws04 = _state[04], ws05 = _state[05], ws06 = _state[06], ws07 = _state[07];
    int ws08 = _state[08], ws09 = _state[09], ws10 = _state[10], ws11 = _state[11];
    int ws12 = _state[12], ws13 = _state[13], ws14 = _state[14], ws15 = _state[15];

    for (int i = 0; i < 10; ++i) {
      // Column rounds

      // Quarter round on (0, 4, 8, 12)
      ws00 = mask32 & (ws00 + ws04);
      ws12 = rotl16(ws12 ^ ws00);
      ws08 = mask32 & (ws08 + ws12);
      ws04 = rotl12(ws04 ^ ws08);
      ws00 = mask32 & (ws00 + ws04);
      ws12 = rotl08(ws12 ^ ws00);
      ws08 = mask32 & (ws08 + ws12);
      ws04 = rotl07(ws04 ^ ws08);

      // Quarter round on (1, 5, 9, 13)
      ws01 = mask32 & (ws01 + ws05);
      ws13 = rotl16(ws13 ^ ws01);
      ws09 = mask32 & (ws09 + ws13);
      ws05 = rotl12(ws05 ^ ws09);
      ws01 = mask32 & (ws01 + ws05);
      ws13 = rotl08(ws13 ^ ws01);
      ws09 = mask32 & (ws09 + ws13);
      ws05 = rotl07(ws05 ^ ws09);

      // Quarter round on (2, 6, 10, 14)
      ws02 = mask32 & (ws02 + ws06);
      ws14 = rotl16(ws14 ^ ws02);
      ws10 = mask32 & (ws10 + ws14);
      ws06 = rotl12(ws06 ^ ws10);
      ws02 = mask32 & (ws02 + ws06);
      ws14 = rotl08(ws14 ^ ws02);
      ws10 = mask32 & (ws10 + ws14);
      ws06 = rotl07(ws06 ^ ws10);

      // Quarter round on (3, 7, 11, 15)
      ws03 = mask32 & (ws03 + ws07);
      ws15 = rotl16(ws15 ^ ws03);
      ws11 = mask32 & (ws11 + ws15);
      ws07 = rotl12(ws07 ^ ws11);
      ws03 = mask32 & (ws03 + ws07);
      ws15 = rotl08(ws15 ^ ws03);
      ws11 = mask32 & (ws11 + ws15);
      ws07 = rotl07(ws07 ^ ws11);

      // Diagonal rounds

      // Quarter round on (0, 5, 10, 15)
      ws00 = mask32 & (ws00 + ws05);
      ws15 = rotl16(ws15 ^ ws00);
      ws10 = mask32 & (ws10 + ws15);
      ws05 = rotl12(ws05 ^ ws10);
      ws00 = mask32 & (ws00 + ws05);
      ws15 = rotl08(ws15 ^ ws00);
      ws10 = mask32 & (ws10 + ws15);
      ws05 = rotl07(ws05 ^ ws10);

      // Quarter round on (1, 6, 11, 12)
      ws01 = mask32 & (ws01 + ws06);
      ws12 = rotl16(ws12 ^ ws01);
      ws11 = mask32 & (ws11 + ws12);
      ws06 = rotl12(ws06 ^ ws11);
      ws01 = mask32 & (ws01 + ws06);
      ws12 = rotl08(ws12 ^ ws01);
      ws11 = mask32 & (ws11 + ws12);
      ws06 = rotl07(ws06 ^ ws11);

      // Quarter round on (2, 7, 8, 13)
      ws02 = mask32 & (ws02 + ws07);
      ws13 = rotl16(ws13 ^ ws02);
      ws08 = mask32 & (ws08 + ws13);
      ws07 = rotl12(ws07 ^ ws08);
      ws02 = mask32 & (ws02 + ws07);
      ws13 = rotl08(ws13 ^ ws02);
      ws08 = mask32 & (ws08 + ws13);
      ws07 = rotl07(ws07 ^ ws08);

      // Quarter round on (3, 4, 9, 14)
      ws03 = mask32 & (ws03 + ws04);
      ws14 = rotl16(ws14 ^ ws03);
      ws09 = mask32 & (ws09 + ws14);
      ws04 = rotl12(ws04 ^ ws09);
      ws03 = mask32 & (ws03 + ws04);
      ws14 = rotl08(ws14 ^ ws03);
      ws09 = mask32 & (ws09 + ws14);
      ws04 = rotl07(ws04 ^ ws09);
    }

    // Save local variables back to working state.
    _state[16] = ws00 + _state[00];
    _state[17] = ws01 + _state[01];
    _state[18] = ws02 + _state[02];
    _state[19] = ws03 + _state[03];
    _state[20] = ws04 + _state[04];
    _state[21] = ws05 + _state[05];
    _state[22] = ws06 + _state[06];
    _state[23] = ws07 + _state[07];
    _state[24] = ws08 + _state[08];
    _state[25] = ws09 + _state[09];
    _state[26] = ws10 + _state[10];
    _state[27] = ws11 + _state[11];
    _state[28] = ws12 + _state[12];
    _state[29] = ws13 + _state[13];
    _state[30] = ws14 + _state[14];
    _state[31] = ws15 + _state[15];
  }
}

class _ChaCha20Sink implements ByteConversionSink {
  const _ChaCha20Sink(this._converter, this._outputSink);

  final ChaCha20 _converter;
  final ByteConversionSink _outputSink;

  @override
  void add(List<int> chunk) => _outputSink.add(
        _converter.convert(chunk),
      );

  @override
  void addSlice(List<int> chunk, int start, int end, bool isLast) {
    add(chunk.sublist(start, end));
    if (isLast) close();
  }

  @override
  void close() => _outputSink.close();
}

import 'dart:convert';
import 'dart:typed_data';

import 'package:chacha/src/utilities.dart';

/// Poly1305 Message Authentication Code (MAC) (RFC 8439).
///
/// Implements a high-speed symmetric MAC algorithm using a 256-bit key.
/// Poly1305 is designed to assure message integrity and authenticity,
/// effectively guarding against tampering in secure communication channels.
final class Poly1305 extends Converter<List<int>, List<int>> {
  // Internal state variables for r, s, accumulator, and g
  int _r0 = 0, _r1 = 0, _r2 = 0, _r3 = 0, _r4 = 0;
  int _s0 = 0, _s1 = 0, _s2 = 0, _s3 = 0;
  int _a0 = 0, _a1 = 0, _a2 = 0, _a3 = 0, _a4 = 0;
  int _g1 = 0, _g2 = 0, _g3 = 0, _g4 = 0;

  // A 17-byte block initialized with 0s, the last byte is set to 1.
  final Uint8List _block = Uint8List(17)..[16] = 1;

  /// Generates a Poly1305 Message Authentication Code (MAC) as per RFC 8439.
  ///
  /// Accepts a 256-bit key for message integrity and authenticity.
  Poly1305({required Uint8List key}) {
    if (key.length != 32) throw ArgumentError('Invalid key');

    // Initialize r from the first 16 bytes of the key.
    _r0 = key[00] | key[01] << 08 | key[02] << 16 | key[03] << 24;
    _r1 = key[03] >>> 02 | key[04] << 06 | key[05] << 14 | key[06] << 22;
    _r2 = key[06] >>> 04 | key[07] << 04 | key[08] << 12 | key[09] << 20;
    _r3 = key[09] >>> 06 | key[10] << 02 | key[11] << 10 | key[12] << 18;
    _r4 = key[13] | key[14] << 08 | key[15] << 16;

    // Clamp r according to RFC 8439 to prevent modular reduction weaknesses.
    _r0 &= 0x03ffffff;
    _r1 &= 0x03ffff03;
    _r2 &= 0x03ffc0ff;
    _r3 &= 0x03f03fff;
    _r4 &= 0x000fffff;

    // Precompute 5*r values for optimization.
    _g1 = 5 * _r1;
    _g2 = 5 * _r2;
    _g3 = 5 * _r3;
    _g4 = 5 * _r4;

    // Initialize s from the second 16 bytes of the key.
    _s0 = key[16] | key[17] << 08 | key[18] << 16 | key[19] << 24;
    _s1 = key[20] | key[21] << 08 | key[22] << 16 | key[23] << 24;
    _s2 = key[24] | key[25] << 08 | key[26] << 16 | key[27] << 24;
    _s3 = key[28] | key[29] << 08 | key[30] << 16 | key[31] << 24;

    // Zero-initialize the accumulator.
    _a0 = _a1 = _a2 = _a3 = _a4 = 0;
  }

  @override
  Uint8List convert(covariant Uint8List input) {
    return (this..add(input)).close();
  }

  void add(Uint8List input) {
    // Process all 16-byte chunks.
    final int blocks = input.length & ~15;
    for (int j = 0; j < blocks; j += 16) {
      _block[00] = input[j];
      _block[01] = input[j + 01];
      _block[02] = input[j + 02];
      _block[03] = input[j + 03];
      _block[04] = input[j + 04];
      _block[05] = input[j + 05];
      _block[06] = input[j + 06];
      _block[07] = input[j + 07];
      _block[08] = input[j + 08];
      _block[09] = input[j + 09];
      _block[10] = input[j + 10];
      _block[11] = input[j + 11];
      _block[12] = input[j + 12];
      _block[13] = input[j + 13];
      _block[14] = input[j + 14];
      _block[15] = input[j + 15];
      _accumulate(_block);
    }

    // Process any remaining bytes.
    final int remaining = input.length % 16;
    if (remaining != 0) {
      for (int j = 0; j < remaining; ++j) {
        _block[j] = input[blocks + j];
      }
      _block[remaining] = 1;
      _block.fillRange(remaining + 1, 17, 0);
      _accumulate(_block);
    }
  }

  void _accumulate(Uint8List chunk) {
    // Temporary variables for modular reduction.
    int d0, d1, d2, d3, d4;

    // Add block to the accumulator: a += n.
    _a0 +=
        chunk[00] |
        chunk[01] << 08 |
        chunk[02] << 16 |
        (chunk[03] & 0x03) << 24;
    _a1 +=
        chunk[03] >>> 02 |
        chunk[04] << 06 |
        chunk[05] << 14 |
        (chunk[06] & 0xF) << 22;
    _a2 +=
        chunk[06] >>> 04 |
        chunk[07] << 04 |
        chunk[08] << 12 |
        (chunk[09] & 0x3F) << 20;
    _a3 +=
        chunk[09] >>> 06 | chunk[10] << 02 | chunk[11] << 10 | chunk[12] << 18;
    _a4 +=
        chunk[13] |
        chunk[14] << 08 |
        chunk[15] << 16 |
        (chunk[16] & 0x03) << 24;

    // Multiply the accumulator by r: a *= r.
    d0 = _a0 * _r0 + _a1 * _g4 + _a2 * _g3 + _a3 * _g2 + _a4 * _g1;
    d1 = _a0 * _r1 + _a1 * _r0 + _a2 * _g4 + _a3 * _g3 + _a4 * _g2;
    d2 = _a0 * _r2 + _a1 * _r1 + _a2 * _r0 + _a3 * _g4 + _a4 * _g3;
    d3 = _a0 * _r3 + _a1 * _r2 + _a2 * _r1 + _a3 * _r0 + _a4 * _g4;
    d4 = _a0 * _r4 + _a1 * _r3 + _a2 * _r2 + _a3 * _r1 + _a4 * _r0;

    // Reduce accumulator by modulo 2^130 - 5: a %= p.
    d1 += d0 >>> 26;
    d2 += d1 >>> 26;
    d3 += d2 >>> 26;
    d4 += d3 >>> 26;
    _a0 = d0 & mask26;
    _a1 = d1 & mask26;
    _a2 = d2 & mask26;
    _a3 = d3 & mask26;
    _a4 = d4 & mask26;
    _a0 += 5 * (d4 >>> 26);
    _a1 += _a0 >>> 26;
    _a0 &= mask26;
  }

  Uint8List close() {
    // Zero out block buffer.
    _block.fillRange(0, 17, 0);

    // Temporary variables final computations.
    int d0, d1, d2, d3, d4;

    // Carry propagation.
    _a1 += _a0 >>> 26;
    _a2 += _a1 >>> 26;
    _a3 += _a2 >>> 26;
    _a4 += _a3 >>> 26;
    _a0 &= mask26;
    _a1 &= mask26;
    _a2 &= mask26;
    _a3 &= mask26;

    // Compute the difference of the accumulator and p: d = a - p.
    d0 = _a0 + 5;
    d1 = _a1 + (d0 >>> 26);
    d2 = _a2 + (d1 >>> 26);
    d3 = _a3 + (d2 >>> 26);
    d4 = _a4 + (d3 >>> 26) - (1 << 26);
    d4 &= mask32;

    // Swap to d if a > prime mod (ensuring result within finite field bounds).
    if ((d4 >>> 31) != 1) {
      _a0 = d0 & mask26;
      _a1 = d1 & mask26;
      _a2 = d2 & mask26;
      _a3 = d3 & mask26;
      _a4 = d4 & mask26;
    }

    // Serialize the result into 32-bit units, accounting for 128-bit overflow.
    _a0 = ((_a0) | (_a1 << 26)) & mask32;
    _a1 = ((_a1 >>> 06) | (_a2 << 20)) & mask32;
    _a2 = ((_a2 >>> 12) | (_a3 << 14)) & mask32;
    _a3 = ((_a3 >>> 18) | (_a4 << 08)) & mask32;

    // Add s to the accumulator for the final tag: a += s.
    _a0 += _s0;
    _a1 += _s1 + (_a0 >>> 32);
    _a2 += _s2 + (_a1 >>> 32);
    _a3 += _s3 + (_a2 >>> 32);

    // Return the final MAC as a Uint8List.
    return Uint32List.fromList(<int>[_a0, _a1, _a2, _a3]).buffer.asUint8List();
  }

  @override
  ByteConversionSink startChunkedConversion(Sink<List<int>> sink) {
    if (sink is! ByteConversionSink) sink = ByteConversionSink.from(sink);
    return _Poly1305Sink(this, sink);
  }
}

final class _Poly1305Sink implements ByteConversionSink {
  const _Poly1305Sink(this._converter, this._outputSink);

  final Poly1305 _converter;
  final ByteConversionSink _outputSink;

  @override
  void add(covariant Uint8List chunk) => _converter.add(chunk);

  @override
  void addSlice(covariant Uint8List chunk, int start, int end, bool isLast) {
    add(chunk.sublist(start, end));
    if (isLast) close();
  }

  @override
  void close() => _outputSink
    ..add(_converter.close())
    ..close();
}

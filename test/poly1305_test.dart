import 'dart:async';
import 'dart:typed_data';
import 'package:chacha/export.dart';
import 'package:test/test.dart';

import 'test_parser.dart';

typedef Poly1305MacTestVector = Map<String, String>;

void main() {
  for (int i = 0; i < poly1305MacTestVectors.length; i++) {
    final Poly1305MacTestVector testVector = poly1305MacTestVectors[i];
    test('Poly1305 Message Authentication Code Test Vector $i', () {
      final Uint8List key = parseBlockHexString(testVector['key']!);
      final Uint8List message = parseBlockHexString(testVector['message']!);
      final Uint8List expected = parseBlockHexString(testVector['tag']!);

      final Uint8List result = Poly1305(key).convert(message);

      expect(result.length, equals(16));
      expect(result, equals(expected));
    });
  }

  for (int i = 0; i < poly1305MacTestVectors.length; i++) {
    final Poly1305MacTestVector testVector = poly1305MacTestVectors[i];
    test('Poly1305 Stream Message Authentication Code Test Vector $i', () async {
      final Uint8List key = parseBlockHexString(testVector['key']!);
      final Uint8List message = parseBlockHexString(testVector['message']!);
      final Uint8List expected = parseBlockHexString(testVector['tag']!);

      final BytesBuilder outputs = BytesBuilder();
      final StreamController<Uint8List> streamController = StreamController<Uint8List>();
      streamController.stream.listen((Uint8List chunk) => outputs.add(chunk));

      final Poly1305 poly1305 = Poly1305(key);
      final Sink<List<int>> inputSink = poly1305.startChunkedConversion(streamController.sink);

      int offset = 0;
      const int chunkSize = 64;
      while (offset < message.length) {
        final int end = (offset + chunkSize < message.length) ? offset + chunkSize : message.length;
        final Uint8List chunk = Uint8List.sublistView(message, offset, end);
        inputSink.add(chunk);
        offset += chunkSize;
      }

      inputSink.close();
      await streamController.close();

      final Uint8List result = outputs.toBytes();

      expect(result.length, equals(expected.length));
      expect(result.length, equals(16));
      expect(result, equals(expected));
    });
  }
}

const List<Poly1305MacTestVector> poly1305MacTestVectors = <Poly1305MacTestVector>[
  // Test Vector #0
  <String, String>{
    'key': '''
      85 d6 be 78 57 55 6d 33 7f 44 52 fe 42 d5 06 a8 
      01 03 80 8a fb 0d b2 fd 4a bf f6 af 41 49 f5 1b
      ''',
    'message': '''
      43 72 79 70 74 6f 67 72 61 70 68 69 63 20 46 6f 72 
      75 6d 20 52 65 73 65 61 72 63 68 20 47 72 6f 75 70
      ''',
    'tag': 'a8 06 1d c1 30 51 36 c6 c2 2b 8b af 0c 01 27 a9',
  },
  // Test Vector #1
  <String, String>{
    'key': '''
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      ''',
    'message': '''
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      ''',
    'tag': '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
  },
  // Test Vector #2
  <String, String>{
    'key': '''
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
      36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e
      ''',
    'message': '''
      41 6e 79 20 73 75 62 6d 69 73 73 69 6f 6e 20 74 
      6f 20 74 68 65 20 49 45 54 46 20 69 6e 74 65 6e 
      64 65 64 20 62 79 20 74 68 65 20 43 6f 6e 74 72 
      69 62 75 74 6f 72 20 66 6f 72 20 70 75 62 6c 69 
      63 61 74 69 6f 6e 20 61 73 20 61 6c 6c 20 6f 72 
      70 61 72 74 20 6f 66 20 61 6e 20 49 45 54 46 20 
      49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 20 6f 
      72 20 52 46 43 20 61 6e 64 20 61 6e 79 20 73 74 
      61 74 65 6d 65 6e 74 20 6d 61 64 65 20 77 69 74 
      68 69 6e 20 74 68 65 20 63 6f 6e 74 65 78 74 20 
      6f 66 20 61 6e 20 49 45 54 46 20 61 63 74 69 76 
      69 74 79 20 69 73 20 63 6f 6e 73 69 64 65 72 65 
      64 20 61 6e 20 22 49 45 54 46 20 43 6f 6e 74 72 
      69 62 75 74 69 6f 6e 22 2e 20 53 75 63 68 20 73 
      74 61 74 65 6d 65 6e 74 73 20 69 6e 63 6c 75 64 
      65 20 6f 72 61 6c 20 73 74 61 74 65 6d 65 6e 74 
      73 20 69 6e 20 49 45 54 46 20 73 65 73 73 69 6f 
      6e 73 2c 20 61 73 20 77 65 6c 6c 20 61 73 20 77 
      72 69 74 74 65 6e 20 61 6e 64 20 65 6c 65 63 74 
      72 6f 6e 69 63 20 63 6f 6d 6d 75 6e 69 63 61 74 
      69 6f 6e 73 20 6d 61 64 65 20 61 74 20 61 6e 79 
      74 69 6d 65 20 6f 72 20 70 6c 61 63 65 2c 20 77 
      68 69 63 68 20 61 72 65 20 61 64 64 72 65 73 73 
      65 64 20 74 6f
      ''',
    'tag': '36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e',
  },
  // Test Vector #3
  <String, String>{
    'key': '''
    36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e 
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    ''',
    'message': '''
      41 6e 79 20 73 75 62 6d 69 73 73 69 6f 6e 20 74 
      6f 20 74 68 65 20 49 45 54 46 20 69 6e 74 65 6e 
      64 65 64 20 62 79 20 74 68 65 20 43 6f 6e 74 72 
      69 62 75 74 6f 72 20 66 6f 72 20 70 75 62 6c 69 
      63 61 74 69 6f 6e 20 61 73 20 61 6c 6c 20 6f 72 
      20 70 61 72 74 20 6f 66 20 61 6e 20 49 45 54 46 
      20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 20 
      6f 72 20 52 46 43 20 61 6e 64 20 61 6e 79 20 73 
      74 61 74 65 6d 65 6e 74 20 6d 61 64 65 20 77 69 
      74 68 69 6e 20 74 68 65 20 63 6f 6e 74 65 78 74 
      20 6f 66 20 61 6e 20 49 45 54 46 20 61 63 74 69 
      76 69 74 79 20 69 73 20 63 6f 6e 73 69 64 65 72 
      65 64 20 61 6e 20 22 49 45 54 46 20 43 6f 6e 74 
      72 69 62 75 74 69 6f 6e 22 2e 20 53 75 63 68 20 
      73 74 61 74 65 6d 65 6e 74 73 20 69 6e 63 6c 75 
      64 65 20 6f 72 61 6c 20 73 74 61 74 65 6d 65 6e 
      74 73 20 69 6e 20 49 45 54 46 20 73 65 73 73 69 
      6f 6e 73 2c 20 61 73 20 77 65 6c 6c 20 61 73 20 
      77 72 69 74 74 65 6e 20 61 6e 64 20 65 6c 65 63 
      74 72 6f 6e 69 63 20 63 6f 6d 6d 75 6e 69 63 61 
      74 69 6f 6e 73 20 6d 61 64 65 20 61 74 20 61 6e 
      79 20 74 69 6d 65 20 6f 72 20 70 6c 61 63 65 2c 
      20 77 68 69 63 68 20 61 72 65 20 61 64 64 72 65 
      73 73 65 64 20 74 6f
      ''',
    'tag': 'f3 47 7e 7c d9 54 17 af 89 a6 b8 79 4c 31 0c f0',
  },
  // Test Vector #4
  <String, String>{
    'key': '''
    1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0 
    47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0
    ''',
    'message': '''
    27 54 77 61 73 20 62 72 69 6c 6c 69 67 2c 20 61 
    6e 64 20 74 68 65 20 73 6c 69 74 68 79 20 74 6f 
    76 65 73 0a 44 69 64 20 67 79 72 65 20 61 6e 64 
    20 67 69 6d 62 6c 65 20 69 6e 20 74 68 65 20 77 
    61 62 65 3a 0a 41 6c 6c 20 6d 69 6d 73 79 20 77 
    65 72 65 20 74 68 65 20 62 6f 72 6f 67 6f 76 65 
    73 2c 0a 41 6e 64 20 74 68 65 20 6d 6f 6d 65 20 
    72 61 74 68 73 20 6f 75 74 67 72 61 62 65 2e
    ''',
    'tag': '45 41 66 9a 7e aa ee 61 e7 08 dc 7c bc c5 eb 62',
  },
  // Test Vector #5
  <String, String>{
    'key': '''
    02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    ''',
    'message': '''
    FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    ''',
    'tag': '03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
  },
  // Test Vector #6
  <String, String>{
    'key': '''
      02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
      FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
      ''',
    'message': '''02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00''',
    'tag': '03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
  },
  // Test Vector #7
  <String, String>{
    'key': '''
      01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      ''',
    'message': '''
      FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF 
      F0 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF 
      11 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      ''',
    'tag': '05 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
  },
  // Test Vector #8
  <String, String>{
    'key': '''
      01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      ''',
    'message': '''
      FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF 
      FB FE FE FE FE FE FE FE FE FE FE FE FE FE FE FE 
      01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
      ''',
    'tag': '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
  },
  // Test Vector #9
  <String, String>{
    'key': '''
      02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      ''',
    'message': '''FD FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF''',
    'tag': 'FA FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF',
  },
  // Test Vector #10
  <String, String>{
    'key': '''
      01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      ''',
    'message': '''
      E3 35 94 D7 50 5E 43 B9 00 00 00 00 00 00 00 00 
      33 94 D7 50 5E 43 79 CD 01 00 00 00 00 00 00 00 
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
      01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      ''',
    'tag': '14 00 00 00 00 00 00 00 55 00 00 00 00 00 00 00',
  },
  // Test Vector #11
  <String, String>{
    'key': '''
      01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      ''',
    'message': '''
      E3 35 94 D7 50 5E 43 B9 00 00 00 00 00 00 00 00 
      33 94 D7 50 5E 43 79 CD 01 00 00 00 00 00 00 00 
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      ''',
    'tag': '13 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
  },
];

// Bit masks.
const int mask26 = 0x03FFFFFF;
const int mask32 = 0xFFFFFFFF;

// Rotates the left bits of a 32-bit unsigned integer.
int rotl16(int value) => mask32 & value << 16 | value >> 16;
int rotl12(int value) => mask32 & value << 12 | value >> 20;
int rotl08(int value) => mask32 & value << 08 | value >> 24;
int rotl07(int value) => mask32 & value << 07 | value >> 25;

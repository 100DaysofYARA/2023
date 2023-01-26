// https://gist.github.com/wxsBSD/bf7b88b27e9f879016b5ce2c778d3e83

// One way to find PE files that start at offset 0 and have a single byte xor
// key.
rule single_byte_xor_pe_and_mz {
  meta:
    author = "Wesley Shields <wxs@atarininja.org>"
    description = "Look for single byte xor of a PE starting at offset 0"
  strings:
    $b = "PE\x00\x00" xor(0x01-0xff)
  condition:
    $b at uint32(0x3c) ^ (uint32(@b[1]) ^ 0x00004550) and
    (uint16(0x00) ^ (uint16(@b[1]) ^ 0x4550)) == 0x5a4d
}

// This detects PE files at offset 0 with a 2 byte xor key
// Interesting point: the two_byte rule also detects the one byte rule because
// a one byte xor key is the same as a two byte xor key where both bytes are
// identical. ;)
rule two_byte_xor_pe_and_mz {
  meta:
    author = "Wesley Shields <wxs@atarininja.org>"
    description = "Look for 2 byte xor of a PE starting at offset 0"
  condition:
    uint16(0) != 0x5a4d and
    uint32((uint16(0x3c) ^ (uint16(0) ^ 0x5a4d)) | ((uint16(0x3e) ^ (uint16(0) ^ 0x5a4d)) << 16)) ^ ((uint16(0) ^ 0x5a4d) | ((uint16(0) ^ 0x5a4d) << 16)) == 0x00004550
}

// Here is a rule that detects 4 byte XOR keys, but it requires that the dwords
// at 0x24 and 0x28 are NULL in the original binary, which is usually true.
rule four_byte_xor_pe_and_mz {
  meta:
    author = "Wesley Shields <wxs@atarininja.org>"
    description = "Look for 4 byte xor of a PE starting at offset 0"
  condition:
    uint16(0) != 0x5a4d and
    uint32(0x28) != 0x00000000 and
    uint32(0x28) == uint32(0x2c) and
    uint32(uint32(0x3c) ^ uint32(0x28)) ^ uint32(0x28) == 0x00004550
}

// Here is a rule that detects single byte incrementing xor of a PE starting at
// offset 0:
rule single_byte_xor_incr_pe_and_mz {
  meta:
    author = "Wesley Shields <wxs@atarininja.org>"
    description = "Look for single byte incrementing xor of a PE starting at offset 0"
  condition:
    uint16(0) != 0x5a4d and
    uint8(0) ^ 0x4d == ((uint8(1) ^ 0x5a) - 1) & 0xff and
    uint32(
      uint32(0x3c) ^ (
        (uint8(0) ^ 0x4d) + 0x3c & 0xff |
        ((uint8(0) ^ 0x4d) + 0x3d & 0xff) << 8 |
        ((uint8(0) ^ 0x4d) + 0x3e & 0xff) << 16 |
        ((uint8(0) ^ 0x4d) + 0x3f & 0xff) << 24
      )
    ) ^ (
      (uint8(0) ^ 0x4d) + (
        uint32(0x3c) ^ (
          (uint8(0) ^ 0x4d) + 0x3c & 0xff |
          ((uint8(0) ^ 0x4d) + 0x3d & 0xff) << 8 |
          ((uint8(0) ^ 0x4d) + 0x3e & 0xff) << 16 |
          ((uint8(0) ^ 0x4d) + 0x3f & 0xff) << 24
        )
      ) & 0xff |
      ((
        (uint8(0) ^ 0x4d) + (
          uint32(0x3c) ^ (
            (uint8(0) ^ 0x4d) + 0x3c & 0xff |
            ((uint8(0) ^ 0x4d) + 0x3d & 0xff) << 8 |
            ((uint8(0) ^ 0x4d) + 0x3e & 0xff) << 16 |
            ((uint8(0) ^ 0x4d) + 0x3f & 0xff) << 24
          )
        ) + 1
      ) & 0xff) << 8 |
      ((
        (uint8(0) ^ 0x4d) + (
          uint32(0x3c) ^ (
            (uint8(0) ^ 0x4d) + 0x3c & 0xff |
            ((uint8(0) ^ 0x4d) + 0x3d & 0xff) << 8 |
            ((uint8(0) ^ 0x4d) + 0x3e & 0xff) << 16 |
            ((uint8(0) ^ 0x4d) + 0x3f & 0xff) << 24
          )
        ) + 2
      ) & 0xff) << 16 |
      ((
        (uint8(0) ^ 0x4d) + (
          uint32(0x3c) ^ (
            (uint8(0) ^ 0x4d) + 0x3c |
            ((uint8(0) ^ 0x4d) + 0x3d & 0xff) << 8 |
            ((uint8(0) ^ 0x4d) + 0x3e & 0xff) << 16 |
            ((uint8(0) ^ 0x4d) + 0x3f & 0xff) << 24
          )
        ) + 3
      ) & 0xff) << 24
    ) == 0x00004550
}

#pragma MIME application/x-xar
#pragma endian big

//  References:
// https://en.wikipedia.org/wiki/Xar_(archiver)
// https://github.com/mackyle/xar/wiki/xarformat

#include <std/mem.pat>
#include <type/magic.pat>
#include <type/size.pat>

// https://github.com/apple-oss-distributions/xar/blob/f67a3a8c43fdd35021fd3d1562b62d2da32b4f4b/xar/include/xar.h.in#L73
enum ChecksumAlg : u32 {
    None    = 0x00,
    SHA1    = 0x01,
    MD5     = 0x02,
    SHA_256 = 0x03,
    SHA_512 = 0x04,
};

// XarHeader
// https://github.com/apple-oss-distributions/xar/blob/f67a3a8c43fdd35021fd3d1562b62d2da32b4f4b/xar/include/xar.h.in#L59
struct XarHeader {
    type::Magic<"xar!"> magic;              // Magic ('xar!')
    type::Size<u16> size;                   // Header Size
    u16 version;                            // Current version is 1
    type::Size<u64> toc_length_compressed;
    type::Size<u64> toc_length_uncompressed;
    ChecksumAlg cksum_alg;
};

struct Xar {
    XarHeader hdr;
    char toc[hdr.toc_length_compressed];    // zlib XML Plist
    char heap[std::mem::size() - $];        // data to be decoded from toc
};


Xar xar @ 0x00;

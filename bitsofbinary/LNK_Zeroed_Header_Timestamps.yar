rule Heuristic_LNK_Zeroed_Header_Timestamp {
    meta:
        author = "BitsOfBinary"
        description = "Detects an LNK file with a creation/write/access timestamp that has been zeroed out"
        reference = "https://bitsofbinary.github.io/yara/2023/01/09/100daysofyara-day-9.html"
        version = "1.1"
        date = "2023-01-09"
        DaysofYARA = "9/100"
        
    condition:
        uint32(0) == 0x0000004C and
        uint32(4) == 0x00021401 and
        uint32(8) == 0x00000000 and
        uint32(12) == 0x000000C0 and
        uint32(16) == 0x46000000 and
        (
            // Creation timestamp
            (
                uint32(28) == 0 and uint32(32) == 0
            ) or
            // Access timestamp
            (
                uint32(36) == 0 and uint32(40) == 0
            ) or
            // Write timestamp
            (
                uint32(44) == 0 and uint32(48) == 0
            )
        )
}
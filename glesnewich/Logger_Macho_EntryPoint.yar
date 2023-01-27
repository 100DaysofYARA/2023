import "console"

rule Logger_Macho_EntryPoint_LCMain
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-27"
        version = "1.0"
        description = "burp out the entry point from LCMain / MAIN_DYLIB load commands"
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
	for any LCMain in (0 .. 0x1000) : (
            	uint32be(LCMain) == 0x28000080 and console.log("LCMain_entry_point_hash: ", hash.md5(uint32(LCMain+8), 16))
        )
}

rule Logger_Macho_EntryPoint_UnixThread_32Bit
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-27"
        version = "1.0"
        description = "burp out the entry point from UnixThread load commands"
    condition:
        uint32be(0x0) == 0xCEFAEDFE and
		for any unix_Thread in (0 .. 0x1000) : (
                	uint32be(unix_Thread) == 0x05000000 and
			uint32be(unix_Thread+8) == 0x01000000
			and console.hex("unix_Thread_x32_entry_point_hash: ", uint32(unix_Thread+0x38))
        )
}

rule Logger_Macho_EntryPoint_UnixThread_64Bit
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-27"
        version = "1.0"
        description = "burp out the entry point from UnixThread load commands"
    condition:
        uint32be(0x0) == 0xCFFAEDFE
		and for any unix_Thread in (0 .. 0x1000) : (
                	uint32be(unix_Thread) == 0x05000000 and
			uint32be(unix_Thread+8) == 0x04000000
			and console.hex("unix_Thread_entry_point_64: ", (uint32(unix_Thread+0x90)) + 0x100000000)
                )
}

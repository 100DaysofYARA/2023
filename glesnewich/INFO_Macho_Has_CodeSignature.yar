rule INFO_Macho_Has_CodeSignature
{
    meta:
        author = "Greg Lesnewich"
        description = "check Macho files for an LC_CODE_SIGNATURE load command"
        date = "2023-01-29"
        version = "1.0"

	condition:
		(uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
        for any cs_sig in (0 .. 0x1000) : (
			uint32be(cs_sig) == 0x1D000000)
}

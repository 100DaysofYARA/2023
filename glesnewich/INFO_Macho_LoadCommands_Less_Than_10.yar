rule INFO_Macho_LoadCommands_Less_Than_10
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-01-24"
		version = "1.0"
		description = "check for Macho files with less than 10 load commands"
	condition:
		(uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
		uint32(0x10) <= 0x0a
}

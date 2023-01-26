rule INFO_Macho_Multiple_Init_Funcs
{
    meta:
        	author = "Greg Lesnewich"
        	description = "check Macho files for multiple initialization methods, via presence of a Mod Init Func section"
        	date = "2023-01-26"
        	version = "1.0"
	strings:
		$section = "mod_init_func" ascii wide
	condition:
		(uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
        	all of them
}

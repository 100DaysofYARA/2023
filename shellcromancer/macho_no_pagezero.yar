/*
https://github.com/kpwn/NULLGuard
> but I haven't yet encountered a non-malicious binary lacking PAGEZERO.
*/
rule macho_no_pagezero_no_module
{
	meta:
		description = "Identify macho executable without a __PAGEZERO segment without the module module."
		author = "@shellcromancer"
		version = "1.2"
		date = "2023.03.02"
		sample = "6ab836d19bc4b69dfe733beef295809e15ace232be0740bc326f58f9d31d8197" // FinSpy
		DaysofYARA = "61/100"

	strings:
		$segment1 = "__PAGEZERO"
		$segment2 = "__ZERO"

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		uint32(0xc) == 0x2 and                   // mach_header->filetype == MH_EXECUTE
		not $segment1 in (0 .. uint32(0x14)) and // 0 to mach_header->sizeofcmds
		not $segment2 in (0 .. uint32(0x14))
}

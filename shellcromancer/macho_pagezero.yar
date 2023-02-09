import "macho"

private rule macho_has_pagezero
{
	meta:
		description = "Identify macho executables with a __PAGEZERO segment."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.09"
		DaysofYARA = "40/100"

	condition:
		// check for section in Universal/FAT binaries
		for all file in macho.file : (
			for any seg in file.segments : (
				seg.segname == "__PAGEZERO"
			)
		) or
		for any seg in macho.segments : (
			seg.segname == "__PAGEZERO"
		)
}

rule macho_no_pagezero
{
	meta:
		description = "Identify macho executable without a __PAGEZERO segment."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.XX"
		sample = "6ab836d19bc4b69dfe733beef295809e15ace232be0740bc326f58f9d31d8197" // FinSpy
		DaysofYARA = "3X/100"

	condition:
		// is Mach-O
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		macho.filetype == macho.MH_EXECUTE and
		not macho_has_pagezero
}

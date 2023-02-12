import "macho"


/*
https://github.com/kpwn/NULLGuard
> but I haven't yet encountered a non-malicious binary lacking PAGEZERO.
*/
rule macho_no_pagezero
{
	meta:
		description = "Identify macho executable without a __PAGEZERO segment."
		author = "@shellcromancer"
		version = "1.1"
		date = "2023.02.09"
		sample = "6ab836d19bc4b69dfe733beef295809e15ace232be0740bc326f58f9d31d8197" // FinSpy
		DaysofYARA = "40/100"
		DaysofYARA = "43/100"

	condition:
		macho.filetype == macho.MH_EXECUTE and
		not for any file in macho.file : (
			not for any seg in file.segments : (
				seg.segname == "__PAGEZERO"
			)
		) and
		not for any seg in macho.segments : (
			seg.segname == "__PAGEZERO"
		)
}

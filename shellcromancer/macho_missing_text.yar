import "macho"

rule macho_no_section_text
{
	meta:
		description = "Identify macho executable without a __text section."
		author = "@shellcromancer"
		version = "1.1"
		date = "2023.02.11"
		sample = "b117f042fe9bac7c7d39eab98891c2465ef45612f5355beea8d3c4ebd0665b45"
		sample = "e94781e3da02c7f1426fd23cbd0a375cceac8766fe79c8bc4d4458d6fe64697c"
		DaysofYARA = "42/100"
		DaysofYARA = "43/100"

	condition:
		macho.filetype == macho.MH_EXECUTE and
		not for any file in macho.file : (
			for any seg in file.segments : (
				seg.segname == "__TEXT" and
				for any sect in seg.sections : (
					sect.sectname == "__text"
				)
			)
		) and
		not for any seg in macho.segments : (
			seg.segname == "__TEXT" and
			for any sect in seg.sections : (
				sect.sectname == "__text"
			)
		)
}

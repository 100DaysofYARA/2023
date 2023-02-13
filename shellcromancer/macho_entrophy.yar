import "math"
import "console"
import "macho"

rule macho_text_entrophy
{
	meta:
		description = "Identify a mach-o binary with 'high' text entrophy."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.13"
		DaysofYARA = "44/100"

	condition:
		// check for section in single arch binaries
		for any seg in macho.segments : (
			seg.segname == "__TEXT" and
			math.entropy(seg.fileoff, seg.fsize) >= 7.8 and
			console.log("__TEXT entropy: ", math.entropy(seg.fileoff, seg.fsize))
		)
}

rule macho_cstring_entrophy
{
	meta:
		description = "Identify a mach-o binary with 'high' cstring entrophy."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.13"
		DaysofYARA = "44/100"

	condition:
		// check for section in single arch binaries
		for any seg in macho.segments : (
			seg.segname == "__TEXT" and
			for any sect in seg.sections : (
				sect.sectname == "__cstring" and
				math.entropy(sect.offset, sect.size) >= 7 and
				console.log("__cstring entropy: ", math.entropy(sect.offset, sect.size))
			)
		)
}

rule macho_cfstring_entrophy
{
	meta:
		description = "Identify a mach-o binary with 'high' cfstring entrophy."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.13"
		DaysofYARA = "44/100"

	condition:
		// check for section in single arch binaries
		for any seg in macho.segments : (
			seg.segname == "__TEXT" and
			for any sect in seg.sections : (
				sect.sectname == "__cfstring" and
				math.entropy(sect.offset, sect.size) >= 7 and
				console.log("__cfstring entropy: ", math.entropy(sect.offset, sect.size))
			)
		)
}

rule macho_ustring_entrophy
{
	meta:
		description = "Identify a mach-o binary with 'high' ustring entrophy."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.13"
		DaysofYARA = "44/100"

	condition:
		// check for section in single arch binaries
		for any seg in macho.segments : (
			seg.segname == "__TEXT" and
			for any sect in seg.sections : (
				sect.sectname == "__ustring" and
				math.entropy(sect.offset, sect.size) >= 4.5 and
				console.log("__ustring entropy: ", math.entropy(sect.offset, sect.size))
			)
		)
}

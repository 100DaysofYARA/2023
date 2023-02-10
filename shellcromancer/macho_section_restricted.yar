import "macho"

rule macho_has_restrict
{
	meta:
		description = "Identify macho executables with a __RESTRICT/__restrict section."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.08"
		reference = "https://github.com/apple-oss-distributions/dyld/blob/c8a445f88f9fc1713db34674e79b00e30723e79d/common/MachOFile.cpp#L1588-L1598"
		sample = "fa82c3ea06d0a6da0167632d31a9b04c0569f00b4c80f921f004ceb9b7e43a7c"
		DaysofYARA = "39/100"

	condition:
		// check for section in Universal/FAT binaries
		for all file in macho.file : (
			for any seg in file.segments : (
				seg.segname == "__RESTRICT" and
				for any sect in seg.sections : (
					sect.sectname == "__restrict"
				)
			)
		) or
		// check for section in single arch binaries
		for any seg in macho.segments : (
			seg.segname == "__RESTRICT" and
			for any sect in seg.sections : (
				sect.sectname == "__restrict"
			)
		)
}

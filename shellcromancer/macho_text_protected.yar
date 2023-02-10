import "macho"

rule macho_text_protected
{
	meta:
		description = "Identify macho executables with the __TEXT segment marked as protected."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.10"
		reference = "https://objective-see.org/blog/blog_0x0D.html"
		reference = "https://ntcore.com/?p=436"
		sample = "58e4e4853c6cfbb43afd49e5238046596ee5b78eca439c7d76bd95a34115a273"
		DaysofYARA = "41/100"

	condition:
		// check for segment protection in Universal/FAT binaries
		for any file in macho.file : (
			for any seg in file.segments : (
				seg.segname == "__TEXT" and
				seg.flags & macho.SG_PROTECTED_VERSION_1
			)
		) or
		// check for segment protection in single arch binaries
		for any seg in macho.segments : (
			seg.segname == "__TEXT" and
			seg.flags & macho.SG_PROTECTED_VERSION_1
		)
}

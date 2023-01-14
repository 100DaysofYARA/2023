rule lang_swift
{
	meta:
		description = "Identify a Swift binary regardless of targetting Apple platforms."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.14"
		DaysofYARA = "14/100"

	strings:
		$swift = "__swift"

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		#swift >= 4
}

rule lang_zig
{
	meta:
		description = "Identify a Zig binary regardless of format (PE, Macho, ELF) or arch. Tested with regular and stripped binaries."
		author = "@shellcromancer"
		version = "1.0"
		last_modified = "2023.01.04"
		sample = "ae3beacdfaa311d48d9c776ddd1257a6aad2b0fe" // zig init-exe macOS

	strings:
		$zig = "zig"

	condition:
		(
			int16(0) == 0x5a4d or      // PE
			uint32(0) == 0x464c457f or // ELF
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		#zig >= 4
}

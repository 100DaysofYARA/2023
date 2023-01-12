rule lang_go_garble
{
	meta:
		description = "Identify a Go binary obfuscated with Garble"
		author = "@shellcromancer"
		version = "1.0"
		last_modified = "2023.01.11"
		reference = "https://github.com/burrowers/garble"
		DaysofYARA = "11/100"

	strings:
		$GoBuildID = /Go build ID: \"[a-zA-Z0-9\/_-]{40,120}\"/ ascii wide
		$runtime = "runtime."
		$reflect = "reflect."
		// https://github.com/burrowers/garble/blob/master/hash.go#L172-L178
		$func = /\*func\(\) \*?[a-zA-Z0-9_]{5,20}\.[a-zA-Z0-9_]{4,19}/

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
		not $GoBuildID and
		#runtime > 4 and
		#reflect > 4 and
		$func
}


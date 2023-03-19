rule mal_macos_rshell
{
	meta:
		description = "Identify macOS rshell backdoor."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.03.19"
		sample = "3a9e72b3810b320fa6826a1273732fee7a8e2b2e5c0fd95b8c36bbab970e830a"
		DaysofYARA = "78/100"

	strings:
		$s0 = "/proc/self/exe"
        $s1 = "/tmp/guid"

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		all of them
}

rule macho_platypus
{
	meta:
		description = "Identify executables built with the Platypus bundler"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.04"
		reference = "https://github.com/sveinbjornt/Platypus"
		reference = "https://www.jamf.com/blog/analyzing-osx-creativeupdater/"
		DaysofYARA = "35/100"

	strings:
		$s1 = { 65 78 65 63 75 74 65 53 63 72 69 70 74 57 69 74 68 [0-3] 50 72 69 76 69 6C 65 67 65 73 }
		$s2 = "STPrivilegedTask"

		$class1 = "ScriptExecController"
		$class2 = "SEController"

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		all of ($s*) and
		1 of ($class*)
}


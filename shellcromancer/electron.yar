rule macho_electron
{
	meta:
		description = "Identify Electron based executables. Stub Macho that loads JS."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.03"
		reference = "https://github.com/electron/electron"
		DaysofYARA = "34/100"

	strings:
		$s1 = "ELECTRON_RUN_AS_NODE"
		$s2 = "Electron Framework.framework"
		$s3 = "_ElectronMain"

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

rule file_asar
{
	meta:
		description = "Identify Electron archives bundles (.asar)"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.03"
		reference = "https://github.com/electron/asar"
		DaysofYARA = "34/100"

	strings:
		$header = { 04 00 00 00 }

		$key1 = "files"
		$key2 = "integrity"
		$key3 = "offset"

	condition:
		$header at 0 and
		all of them
}


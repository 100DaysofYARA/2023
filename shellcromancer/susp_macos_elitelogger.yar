rule susp_macos_elite_keylogger
{
	meta:
		description = "Identify macOS Elite Keylogger."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.03.06"
		sample = "edf5033a273bfbaebc721eb8dc30370bc0cd2b596d40051e19fdd32475d62194"
		DaysofYARA = "65/100"

	strings:
		$s0 = "Install_Elite_Keylogger"
		$s1 = { 45 6C 69 74 65 [0-1] 4B 65 79 6C 6F 67 67 65 72 }
		$s2 = "congratInvisible"

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

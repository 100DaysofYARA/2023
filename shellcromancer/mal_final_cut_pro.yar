rule mal_final_cut_pro
{
	meta:
		description = "Identify macOS Logic Pro X Cryptocurrency malware"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.25"
		sample = "33114dd11009871fa6ad54797b45874d310eed2ad2f1da797f774701363be054"
		reference = "https://www.jamf.com/blog/cryptojacking-macos-malware-discovered-by-jamf-threat-labs/"
		DaysofYARA = "56/100"

	strings:
		$s1 = "Task %@ is not running"
		$s2 = "STPrivilegedTaskDidTerminateNotification"
		$s3 = "I2P"
		$s4 = "FileExists"
		$s5 = "DirExists"
		$s6 = "Traktor"

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		4 of them
}

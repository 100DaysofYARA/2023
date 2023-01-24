rule mal_orat
{
	meta:
		description = "Identify the unpacked orat backdoors"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.24"
		reference = "https://www.sentinelone.com/blog/from-the-front-lines-unsigned-macos-orat-malware-gambles-for-the-win/"
		sample = "0e4a71b465f69e7cc4fa88f0c28c4ae69936577e678db0696b215e8d26503f8f"
		DaysofYARA = "24/100"

	strings:
		$a1 = "/agent/info"
		$a2 = "/agent/ping"
		$a3 = "/agent/upload"
		$a4 = "/agent/download"

		$b2 = "JoinTime"
		$b3 = "[(%s)==(%s)]<===>[(%s)==(%s)]"

		$c1 = "RK_NET"
		$c2 = "RK_ADDR"
		$c3 = "RK_NET"



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
		30% of them
}


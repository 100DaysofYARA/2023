rule mal_macos_xslcmd
{
	meta:
		description = "Identify macOS XslCmd malware."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.03.03"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/osx.xslcmd"
		sample = "1db30d5b2bb24bcc4b68d647c6a2e96d984a13a28cc5f17596b3bfe316cca342"
		DaysofYARA = "62/100"

	strings:
		$s0 = "/.fontset/"
		$s1 = "pxupdate.ini"
		$s2 = "dump address: 0x%p, len 0x%x"
		$s3 = { 2f 74 6d 70 2f 6f 73 [3-4] 2e 6c 6f 67 }

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

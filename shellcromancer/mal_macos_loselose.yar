rule mal_macos_loselose : OSXLoseLoseA
{
	meta:
		description = "Identify macOS LoseLose malware "
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.03.09"
		reference = "http://loselose.net"
		sample = "0e600ad7a40d1d935d85a47f1230a74e3ad4fd673177677827df9bca5bcb83e2"
		DaysofYARA = "68/100"

	strings:
		$s1 = "/Users/zachgage/Projects/"
		$s2 = "zach/virus/build/virus.build"
		$s3 = "ofxDirList - attempting to open %s"
		$s4 = "result in files on your hard drive"
		$s5 = "lose/lose"

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

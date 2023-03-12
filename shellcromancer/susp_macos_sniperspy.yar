

rule susp_macos_sniperspy
{
	meta:
		description = "Identify the macOS SniperSpy backdoor."
		author = "@shellcromancer"
		version = "0.1"
		date = "2023.02.12"
		reference = "https://www.flexispy.com/en/compatibility.htm?utm_source=sniperspy"
		sample = "529a659259e1a816d9192aab7b97d0281776ab8ef360d2c6c95e14a03ccda06a"
		DaysofYARA = "71/100"

	strings:
		$s1 = "/Shared/.syslogagent/syslogset.plist"
		$s2 = "syslogagent.app"
		$s3 = "sniperspy"


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

rule mal_macos_coinminer_xmrig
{
	meta:
		description = "Identify macOS CoinMiner malware."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.03.05"
		sample = "fabe0b41fb5bce6bda8812197ffd74571fc9e8a5a51767bcceef37458e809c5c"
		DaysofYARA = "64/100"

	strings:
		$s0 = "XMRig"
		$s1 = "cryptonight"
		$s3 = "user\": \"pshp"
		$s4 = "pass\": \"x"
		$s5 = "url\": \"127.0.0.1:"

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



rule mal_macos_weaponx
{
	meta:
		description = "Identify the macOS WeaponX rootkit PoC."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.03.11"
		reference = "http://phrack.org/issues/66/16.html"
		sample = "5cf59f415ee67784227a2e9009ba9b3b3866d28d3d8f2b2c174368e1afc6ef96"
		DaysofYARA = "70/100"

	strings:
		$s0 = "r00t"
		$s1 = "com.nemo.kext.WeaponX"
		$s2 = "_antimain"
		$s3 = "_realmain"

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		3 of them
}

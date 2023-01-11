rule file_dmg
{
	meta:
		description = "Identify Apple DMG files."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.07"
		sample = "9ceea14642a1fa4bc5df189311a9e01303e397531a76554b4d975301c0b0e5c8"
		reference = "http://newosxbook.com/DMG.html"
		DaysofYARA = "7/100"

	strings:
		$plist = "</plist>"
		$magic = "koly"

	condition:
		$plist and
		for any of ($magic) : (
			uint32be(@ + 4) == 4
		)
}

rule file_dmg_condition_only
{
	meta:
		description = "Identify Apple DMG files."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.10"
		sample = "9ceea14642a1fa4bc5df189311a9e01303e397531a76554b4d975301c0b0e5c8"
		reference = "http://newosxbook.com/DMG.html"
		DaysofYARA = "10/100"

	condition:
		uint32be(filesize - 512) == 0x6b6f6c79
}

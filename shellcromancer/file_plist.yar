rule file_plist
{
	meta:
		description = "Identify Apple Property List Files (binary, XML or otherwise)."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.12"
		reference = "http://newosxbook.com/bonus/bplist.pdf"
		reference = "https://medium.com/@karaiskc/understanding-apples-binary-property-list-format-281e6da00dbd"
		DaysofYARA = "12/100"

	strings:
		$bplist = { 62 70 6C 69 73 74 3? 3? }
		$dtd = "http://www.apple.com/DTDs/PropertyList-1.0.dtd"

	condition:
		$bplist at 0 or
		$dtd
}

rule plist_persistence
{
	meta:
		description = "Identify common Property List keys in malware."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.12"
		reference = "https://www.launchd.info"
		DaysofYARA = "12/100"

	strings:
		$s1 = "RunAtLoad"
		$s2 = "KeepAlive"
		$s3 = "UserName"

	condition:
		file_plist and
		any of them
}

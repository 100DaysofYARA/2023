// source: /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara
rule XProtect_snowdrift
{
	meta:
		description = "SNOWDRIFT"
	strings:
		$a = "https://api.pcloud.com/getfilelink?path=%@&forcedownload=1"
		$b = "-[Management initCloud:access_token:]"
		$c = "*.doc;*.docx;*.xls;*.xlsx;*.ppt;*.pptx;*.hwp;*.hwpx;*.csv;*.pdf;*.rtf;*.amr;*.3gp;*.m4a;*.txt;*.mp3;*.jpg;*.eml;*.emlx"
	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		2 of them
}

rule mal_macos_cloudmensis
{
	meta:
		description = "Identify the CloudMensis/SNOWDRIFT malware"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.21"
		reference = "https://www.welivesecurity.com/2022/07/19/i-see-what-you-did-there-look-cloudmensis-macos-spyware/"
		sample = "317ce26cae14dc9a5e4d4667f00fee771b4543e91c944580bbb136e7fe339427"
		DaysofYARA = "52/100"

	strings:
		$ = "SearchAndMoveFS:removable:"
		$ = "SavePetConfigData"
		$ = "csrutil status | grep disabled"
		$ = "CheckScreenSaverState"

	condition:
		all of them

}

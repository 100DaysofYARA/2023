include "file_macho.yar"

rule mal_macos_cointicker
{
	meta:
		description = "Identify macOS CoinTicker malware methods"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.21"
		reference = "https://www.malwarebytes.com/blog/news/2018/10/mac-cryptocurrency-ticker-app-installs-backdoors"
		sample = "c344730f41f52a2edabf95730389216a9327d6acc98346e5738b3eb99631634d"
		DaysofYARA = "21/100"

	strings:
		$s1 = "relounch"
		$s2 = "This is a test"
		$s3 = "Super long string here"

	condition:
		file_macho and
		any of them
}

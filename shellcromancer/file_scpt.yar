rule file_applescript
{
	meta:
		description = "Identify Compiled AppleScript Programs"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.13"
		reference = "https://applescriptlibrary.wordpress.com"
		reference = "https://www.sentinelone.com/labs/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/"
		sample = "b954af3ee83e5dd5b8c45268798f1f9f4b82ecb06f0b95bf8fb985f225c2b6af"
		DaysofYARA = "13/100"

	strings:
		$head = { 46 61 73 64 55 41 53 20 }
		$tail = { fa de de ad }

	condition:
		$head at 0 and
		$tail at filesize - 4
}

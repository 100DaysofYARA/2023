rule file_jxa_script
{
	meta:
		description = "Identify JavaScript for Automation Programs"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.16"
		reference = "https://tylergaw.com/blog/building-osx-apps-with-js/"
		reference = "https://posts.specterops.io/persistent-jxa-66e1c3cd1cf5"
		DaysofYARA = "16/100"

	strings:
		$head = { 4A 73 4F 73 61 44 41 53 }
		$type = { 6A 73 63 72 }
		$tail = { fa de de ad }

	condition:
		$head at 0 and
		$type and
		$tail at filesize - 4
}

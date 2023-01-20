include "file_scpt_jxa.yar"
include "file_scpt.yar"
include "file_macho.yar"

rule susp_macos_browser_stealer
{
	meta:
		description = "Identify macOS runables that target browser history/credentials."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.19"
		reference = "https://tylergaw.com/blog/building-osx-apps-with-js/"
		reference = "https://posts.specterops.io/persistent-jxa-66e1c3cd1cf5"
		DaysofYARA = "19/100"

	strings:
		$safari1 = "/Library/Safari/History.db"
		$safari2 = "/Library/Cookies"
		$chrome = "/Library/Application Support/Google/Chrome/Default/History"
		$ffox = "/Library/Application Support/Firefox/Profiles/"

		$sec = "security find-generic-password"

	condition:
		any of (file_*) and
		any of them
}

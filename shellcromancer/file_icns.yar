import "console"

rule file_icns
{
	meta:
		description = "Identify Apple Icon files (.icns)"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.20"
		reference = "https://en.wikipedia.org/wiki/Apple_Icon_Image_format"
		DaysofYARA = "51/100"

	strings:
		$header = "icns" private
		$ostype = { ( 69 63 | 49 43 ) ?? ?? }

	condition:
		$header at 0 and
		$ostype at 8
}

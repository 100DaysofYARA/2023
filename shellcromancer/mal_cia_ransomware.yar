rule mal_cia_ransomware
{
	meta:
		description = "Identify macOS CIA ransomware"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.29"
		sample = "1de673936636733112f29c8b8e15867ef1f288c5e5799615348f7a569c523de4"
		DaysofYARA = "29/100"

	strings:
		$log = "tagging file: %s"
		$name = "http://%s:8080/readme"
		$cia = "cia.gov was here"
		$background = "github.com/reujab/wallpaper.SetFromURL"
		$destop = "/Desktop2"
		$image = "http://%s:8080/imageinconsistent"

	condition:
		all of them
}

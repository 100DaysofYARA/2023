rule file_onenote
{
	meta:
		description = "Identify OneNote "
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.20"
		reference = "https://interoperability.blob.core.windows.net/files/MS-ONE/%5bMS-ONE%5d.pdf"
		DaysofYARA = "20/100"

	condition:
		uint32be(0) == 0xE4525C7B
}

rule susp_onenote_embedded_pe
{
	meta:
		description = "Identify OneNote"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.20"
		reference = "https://blog.osarmor.com/319/onenote-attachment-delivers-asyncrat-malware/m"
		reference = "https://www.joesandbox.com/analysis/787620/0/html"
		sample = "b13c979dae8236f1e7f322712b774cedb05850c989fc08312a348e2385ed1b21"
		DaysofYARA = "20/100"

	strings:
		$pe = "!This program cannot be run in DOS mode"

	condition:
		file_onenote and
		any of them
}

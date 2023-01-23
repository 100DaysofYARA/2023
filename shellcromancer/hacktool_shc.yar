
rule hacktool_shc
{
	meta:
		description = "Identify ELF executables built with the shc compiler"
		author = "@shellcromancer"
		version = "1.0"
		last_modified = "2023.01.22"
		reference = "https://neurobin.org/projects/softwares/unix/shc/"
		reference = "https://asec.ahnlab.com/en/45182/"
		sample = "d2626acc7753a067014f9d5726f0e44ceba1063a1cd193e7004351c90875f071"
		DaysofYARA = "22/100"

	strings:
		$s1 = "neither argv[0] nor"
		$s2 = "%s%s%s: %s"

	condition:
		uint32(0) == 0x464c457f and // ELF
		all of them
}

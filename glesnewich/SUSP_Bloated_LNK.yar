rule SUSP_Bloated_LNK
{
	meta:
		author = "Greg Lesnewich"
		description = "check for LNK files with a size over 250KB - examples from Janicab (PDF) and GOLDBACKDOOR (Doc) and MustangPanda (HTML)"
		date = "2023-01-02"
		version = "1.0"
		hash = "120ca851663ef0ebef585d716c9e2ba67bd4870865160fec3b853156be1159c5"
		DaysofYARA = "2/100"

	condition:
		uint32be(0x0) == 0x4C000000 and
		filesize > 250KB
}

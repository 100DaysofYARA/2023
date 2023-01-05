rule SUSP_LNK_Embedded_WordDoc
{
	meta:
		author = "Greg Lesnewich"
		description = "check for LNK files with indications of the Word program or an embedded doc"
		date = "2023-01-02"
		version = "1.0"
		hash = "120ca851663ef0ebef585d716c9e2ba67bd4870865160fec3b853156be1159c5"
		DaysofYARA = "2/100"

	strings:
		$doc_header = {D0 CF 11 E0 A1 B1 1A E1}
		$icon_loc = "C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.exe" ascii wide
	condition:
		uint32be(0x0) == 0x4C000000 and
		filesize > 10KB and
		any of them
}

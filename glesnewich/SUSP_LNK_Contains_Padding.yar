rule SUSP_LNK_Contains_Padding
{
	meta:
		author = "Greg Lesnewich"
		description = "Look for LNK files with space padded commandline args"
		date = "2023-01-05"
		version = "1.0"
		DaysofYARA = "5/100"

	strings:
		$padding = {20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 }
	condition:
		uint32be(0x0) == 0x4c000000 and $padding
}

import "lnk"

rule SUSP_LNK_CommandLine_Padding
{
	meta:
		author = "Greg Lesnewich"
		description = "Look for LNK files with space padded commandline args"
		date = "2023-01-05"
		version = "1.0"
		DaysofYARA = "5/100"

	condition:
		uint32be(0x0) == 0x4C000000 and
		lnk.command_line_arguments contains " \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00 "
}

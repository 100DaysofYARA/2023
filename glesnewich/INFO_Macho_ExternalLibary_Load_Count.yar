rule INFO_Macho_ExternalLibary_Load_Count_0
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-01-24"
		version = "1.0"
        	description = "highlight the volume of external libraries loaded by a Macho sample, derived from number of LOAD_DYLIB commands in the LoadCommand header"

	strings:
		$load_cmd = {00 00 00 00 0C 00 00 00}
	condition:
		(uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
		#load_cmd in (0 .. 0x1000) == 0

}


rule INFO_Macho_ExternalLibary_Load_Count_1
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-01-24"
		version = "1.0"
        	description = "highlight the volume of external libraries loaded by a Macho sample, derived from number of LOAD_DYLIB commands in the LoadCommand header"

	strings:
		$load_cmd = {00 00 00 00 0C 00 00 00}
	condition:
		(uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
		#load_cmd in (0 .. 0x1000) == 1

}


rule INFO_Macho_ExternalLibary_Load_Count_2
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-01-24"
		version = "1.0"
        	description = "highlight the volume of external libraries loaded by a Macho sample, derived from number of LOAD_DYLIB commands in the LoadCommand header"

	strings:
		$load_cmd = {00 00 00 00 0C 00 00 00}
	condition:
		(uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
		#load_cmd in (0 .. 0x1000) == 2

}


rule INFO_Macho_ExternalLibary_Load_Count_3
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-01-24"
		version = "1.0"
        	description = "highlight the volume of external libraries loaded by a Macho sample, derived from number of LOAD_DYLIB commands in the LoadCommand header"

	strings:
		$load_cmd = {00 00 00 00 0C 00 00 00}
	condition:
		(uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
		#load_cmd in (0 .. 0x1000) == 3

}

rule INFO_Macho_ExternalLibary_Load_Count_4
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-01-24"
		version = "1.0"
        	description = "highlight the volume of external libraries loaded by a Macho sample, derived from number of LOAD_DYLIB commands in the LoadCommand header"

	strings:
		$load_cmd = {00 00 00 00 0C 00 00 00}
	condition:
		(uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
		#load_cmd in (0 .. 0x1000) == 4

}

rule INFO_Macho_ExternalLibary_Load_Count_5
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-01-24"
		version = "1.0"
        	description = "highlight the volume of external libraries loaded by a Macho sample, derived from number of LOAD_DYLIB commands in the LoadCommand header"

	strings:
		$load_cmd = {00 00 00 00 0C 00 00 00}
	condition:
		(uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
		#load_cmd in (0 .. 0x1000) == 5

}

rule INFO_Macho_ExternalLibary_Load_Count_More_Than_5
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-01-24"
		version = "1.0"
        	description = "highlight the volume of external libraries loaded by a Macho sample, derived from number of LOAD_DYLIB commands in the LoadCommand header"

	strings:
		$load_cmd = {00 00 00 00 0C 00 00 00}
	condition:
		(uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
		#load_cmd in (0 .. 0x1000) > 5

}

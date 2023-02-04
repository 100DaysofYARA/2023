rule SUSP_Macho_Second_Embedded_Macho
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-02-04"
		version = "1.0"
		description = "check Macho samples for additional Macho header structures"

	strings:
		$s = {(CFFAEDFE|CEFAEDFE) [30-38] 5F 5F 50 41 47 45 5A 45 52 4F [20-70] 5F 5F 54 45 58 54}

	condition:
		(uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
		#s >= 2
}


rule SUSP_Macho_Second_MagicBytes
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-02-04"
		version = "1.0"
		description = "check Macho samples for additional Macho magic bytes"

	strings:
		$CFFAEDFE = {CFFAEDFE}
		$CEFAEDFE = {CEFAEDFE}
	condition:
		(uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
		(#CFFAEDFE >= 2 or #CEFAEDFE >= 2)
}

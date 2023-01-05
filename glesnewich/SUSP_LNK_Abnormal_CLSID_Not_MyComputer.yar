rule SUSP_LNK_Abnormal_CLSID_Not_MyComputer
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-01-04"
		version = "1.0"
		hash = "120ca851663ef0ebef585d716c9e2ba67bd4870865160fec3b853156be1159c5"
		DaysofYARA = "4/100"

	strings:
		$clsid = {E0 4F D0 20 EA 3A 69 10 A2 D8 08 00 2B 30 30 9D}
	condition:
		uint32be(0x0) == 0x4C000000 and none of them
}

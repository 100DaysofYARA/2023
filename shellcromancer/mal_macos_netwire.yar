
rule mal_macos_netwire
{
	meta:
		description = "Identify the macOS Netwire Client"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.03.10"
		sample = "07a4e04ee8b4c8dc0f7507f56dc24db00537d4637afee43dbb9357d4d54f6ff4"
		DaysofYARA = "69/100"

	strings:
		$s0 = "User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko"
		$s1 = "%PATH%"
		$s2 = "%HOME%"
		$s3 = "%USER%"

		$c0 = {
			e8 [4]         //      call    sub_9487
			83 c4 0c       //      add     esp, 0xc
			bf ff 00 00 00 //      mov     edi, 0xff
			ba f8 e? ?? ?? //      mov     edx, data_e2f8
			89 d9          //      mov     ecx, ebx {var_6014}
			57             //      push    edi {var_78b4}  {0xff}
			68 ?? ?? ?? ?? //      push    data_e2f8 {var_78b8}
			57             //      push    edi {var_78bc}  {0xff}
			e8 [4]         //      call    sub_9502
			83 c4 0c       //      add     esp, 0xc
			ba f8 e? ?? ?? //      mov     edx, data_e3f8
			89 d9          //      mov     ecx, ebx {var_6014}
			57             //      push    edi {var_78b4}  {0xff}
			68 ?? ?? ?? ?? //      push    data_e3f8 {var_78b8}
			57             //      push    edi {var_78bc}  {0xff}
			e8 [4]         //      call    sub_9502
			83 c4 0c       //      add     esp, 0xc
			bf 20 00 00 00 //      mov     edi, 0x20
			ba f8 e? ?? ?? //      mov     edx, data_e4f8
			89 d9          //      mov     ecx, ebx {var_6014}
			57             //      push    edi {var_78b4}  {0x20}
			68 ?? ?? ?? ?? //      push    data_e4f8 {var_78b8}
			57             //      push    edi {var_78bc}  {0x20}
			e8 [4]         //      call    sub_9502
			83 c4 0c       //      add     esp, 0xc
			ba 2a e? ?? ?? //      mov     edx, data_e52a
			89 d9          //      mov     ecx, ebx {var_6014}
			56             //      push    esi {var_78b4}  {0x10}
			68 ?? ?? ?? ?? //      push    data_e52a {var_78b8}
			56             //      push    esi {var_78bc}  {0x10}
			e8 [3] ??      //      call    sub_9502
		}

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		2 of them
}

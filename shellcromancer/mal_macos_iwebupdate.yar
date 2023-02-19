rule mal_iwebservices
{
	meta:
		description = "Identify the iWebServices malware"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.19"
		reference = "https://objective-see.org/blog/blog_0x72.html"
		sample = "3e66e664b05b695b0b018d3539412e6643d036c6d1000e03b399986252bddbfb"
		DaysofYARA = "50/100"

	strings:
		$s1 = "/update.php"
		$s2 = "/install.php"
		$s3 = "/tmp/iwup.tmp"

		$c1 = {
			e8 [4]         // call    _strchr
			49 89 c4       // mov     r12, rax
			45 31 ed       // xor     r13d, r13d  {0x0}
			4d 85 e4       // test    r12, r12
			74 ??          // je      0x1000018ab
			4c 89 e0       // mov     rax, r12
			49 ff c4       // inc     r12
			c6 00 00       // mov     byte [rax], 0x0
			be 3b 00 00 00 // mov     esi, 0x3b
			4c 89 e7       // mov     rdi, r12
			e8 [4]         // call    _strchr
			48 89 c3       // mov     rbx, rax
			45 31 ed       // xor     r13d, r13d  {0x0}
			48 85 db       // test    rbx, rbx
			74 ??          // je      0x1000018ab
			48 89 d8       // mov     rax, rbx
			48 ff c3       // inc     rbx
			c6 00 00       // mov     byte [rax], 0x0
			be 3b 00 00 00 // mov     esi, 0x3b
			48 89 df       // mov     rdi, rbx
			e8 [4]         // call    _strchr
			45 31 ed       // xor     r13d, r13d  {0x0}
			48 85 c0       // test    rax, rax
			74 ??          // je      0x10000188b
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
		all of ($s*) or
		all of ($c*)
}


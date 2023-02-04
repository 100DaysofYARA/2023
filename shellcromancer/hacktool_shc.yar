
rule hacktool_shc
{
	meta:
		description = "Identify ELF executables built with the shc compiler"
		author = "@shellcromancer"
		version = "1.1"
		last_modified = "2023.02.01"
		reference = "https://neurobin.org/projects/softwares/unix/shc/"
		reference = "https://asec.ahnlab.com/en/45182/"
		sample = "d2626acc7753a067014f9d5726f0e44ceba1063a1cd193e7004351c90875f071"
		DaysofYARA = "22/100"
		DaysofYARA = "32/100"

	strings:
		$s1 = "neither argv[0] nor"
		$s2 = "%s%s%s: %s"

		$default_expiry = "jahidulhamid@yahoo.com"

	condition:
		(
			int16(0) == 0x5a4d or      // PE
			uint32(0) == 0x464c457f or // ELF
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		2 of them
}



rule hacktool_shc_rm_arg
{
	meta:
		description = "Identify executables built with the shc compiler using the rmargs function"
		author = "@shellcromancer"
		version = "1.1"
		last_modified = "2023.02.01"
		reference = "https://neurobin.org/projects/softwares/unix/shc/"
		reference = "https://asec.ahnlab.com/en/45182/"
		sample = "d2626acc7753a067014f9d5726f0e44ceba1063a1cd193e7004351c90875f071"
		DaysofYARA = "23/100"
		DaysofYARA = "32/100"

	strings:
		$rmargs = {
			48 83 7D F8 00 // cmp qword [rbp - 8], 0
			74 ??          // je 0x94
			48 8B 45 F8    // mov rax, qword [rbp - 8]
			48 8B 00       // mov rax, qword [rax]
			48 85 C0       // test rax, rax
			74 ??          // je 0x88
			48 8B 45 F8    // mov rax, qword [rbp - 8]
			48 8B 00       // mov rax, qword [rax]
			48 3B 45 F0    // cmp rax, qword [rbp - 0x10]
			75 ??          // jne 0x3d
			EB ??          // jmp 0x79
			48 8B 45 F8    // mov rax, qword [rbp - 8]
			48 83 C0 08    // add rax, 8
			48 8B 10       // mov rdx, qword [rax]
			48 8B 45 F8    // mov rax, qword [rbp - 8]
			48 89 10       // mov qword [rax], rdx
			48 83 45 F8 08 // add qword [rbp - 8], 8
			48 83 7D F8 00 // cmp qword [rbp - 8], 0
			74 ??          // je 0x6e
			48 8B 45 F8    // mov rax, qword [rbp - 8]
			48 8B 00       // mov rax, qword [rax]
			48 85 C0       // test rax, rax
		}

		$clang_0x10000357e = {
			48 83 7d f8 00 //   cmp     qword [rbp-0x8 {var_10}], 0x0
			88 45 ef       //   mov     byte [rbp-0x11 {var_19_1}], al  {0x0}
			0f 84 [4]      //   je      0x1000035b0
			48 8b 4d f8    //   mov     rcx, qword [rbp-0x8 {var_10}]
			31 c0          //   xor     eax, eax  {0x0}
			48 83 39 00    //   cmp     qword [rcx], 0x0
			88 45 ef       //   mov     byte [rbp-0x11 {var_19_1}], al  {0x0}
			0f 84 [4]      //   je      0x1000035b0
			48 8b 45 f8    //   mov     rax, qword [rbp-0x8 {var_10}]
			48 8b 00       //   mov     rax, qword [rax]
			48 3b 45 f0    //   cmp     rax, qword [rbp-0x10 {var_18}]
			0f 95 c0       //   setne   al
			88 45 ef       //   mov     byte [rbp-0x11 {var_19_1}], al
			8a 45 ef       //   mov     al, byte [rbp-0x11 {var_19_1}]
			a8 01          //   test    al, 0x1
			0f 85 [4]      //   jne     0x1000035c0
			e9 [4]         //   jmp     0x1000035d6
			e9 [4]         //   jmp     0x1000035c5
			48 8b 45 f8    //   mov     rax, qword [rbp-0x8 {var_10}]
			48 83 c0 08    //   add     rax, 0x8
			48 89 45 f8    //   mov     qword [rbp-0x8 {var_10}], rax
			e9 [4]         //   jmp     0x10000357c
			e9 [4]         //   jmp     0x1000035db
			31 c0          //   xor     eax, eax  {0x0}
			48 83 7d f8 00 //   cmp     qword [rbp-0x8 {var_10}], 0x0
			88 45 ee       //   mov     byte [rbp-0x12 {var_1a_1}], al  {0x0}
			0f 84 [4]      //   je      0x1000035f9
			48 8b 45 f8    //   mov     rax, qword [rbp-0x8 {var_10}]
			48 83 38 00    //   cmp     qword [rax], 0x0
			0f 95 c0       //   setne   al
			88 45 ee       //   mov     byte [rbp-0x12 {var_1a_1}], al
			8a 45 ee       //   mov     al, byte [rbp-0x12 {var_1a_1}]
			a8 01          //   test    al, 0x1
			0f 85 [4]      //   jne     0x100003609
			e9 [4]         //   jmp     0x100003629
			48 8b 45 f8    //   mov     rax, qword [rbp-0x8 {var_10}]
			48 8b 48 08    //   mov     rcx, qword [rax+0x8]
			48 8b 45 f8    //   mov     rax, qword [rbp-0x8 {var_10}]
		}
	condition:
		(
			int16(0) == 0x5a4d or      // PE
			uint32(0) == 0x464c457f or // ELF
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		any of them
}



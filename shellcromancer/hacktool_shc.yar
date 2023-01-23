
rule hacktool_shc
{
	meta:
		description = "Identify ELF executables built with the shc compiler"
		author = "@shellcromancer"
		version = "1.0"
		last_modified = "2023.01.22"
		reference = "https://neurobin.org/projects/softwares/unix/shc/"
		reference = "https://asec.ahnlab.com/en/45182/"
		sample = "d2626acc7753a067014f9d5726f0e44ceba1063a1cd193e7004351c90875f071"
		DaysofYARA = "22/100"

	strings:
		$s1 = "neither argv[0] nor"
		$s2 = "%s%s%s: %s"

	condition:
		uint32(0) == 0x464c457f and // ELF
		all of them
}



rule hacktool_shc_rm_arg
{
	meta:
		description = "Identify ELF executables built with the shc compiler using the rmargs function"
		author = "@shellcromancer"
		version = "1.0"
		last_modified = "2023.01.23"
		reference = "https://neurobin.org/projects/softwares/unix/shc/"
		reference = "https://asec.ahnlab.com/en/45182/"
		sample = "d2626acc7753a067014f9d5726f0e44ceba1063a1cd193e7004351c90875f071"
		DaysofYARA = "23/100"

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

	condition:
		uint32(0) == 0x464c457f and // ELF
		all of them
}

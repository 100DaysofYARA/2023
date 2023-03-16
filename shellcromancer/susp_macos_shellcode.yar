rule susp_macos_shellcode
{
	meta:
		description = "Identify macOS shellcode from @evilbit."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.03.15"
		reference = "https://github.com/theevilbit/shellcode/tree/master/osx/x64"
		DaysofYARA = "74/100"

	strings:
		$binsh = {
			48 31 f6                      // xor     rsi, rsi  {0x0}
			56                            // push    rsi {var_8}  {0x0}
			48 bf 2f 2f 62 69 6e 2f 73 68 // mov     rdi, 0x68732f6e69622f2f
			57                            // push    rdi {var_10}  {0x68732f6e69622f2f}
			48 89 e7                      // mov     rdi, rsp {var_10}
			48 31 d2                      // xor     rdx, rdx  {0x0}
			48 31 c0                      // xor     rax, rax  {0x0}
			b0 02                         // mov     al, 0x2
			48 c1 c8 28                   // ror     rax, 0x28  {0x2000000}
			b0 3b                         // mov     al, 0x3b
			0f 05                         // syscall
		}

		$bindsc = {
			48 31 ff                      //  xor     rdi, rdi  {sub_0}
			40 b7 02                      //  mov     dil, 0x2
			48 31 f6                      //  xor     rsi, rsi  {sub_0}
			40 b6 01                      //  mov     sil, 0x1
			48 31 d2                      //  xor     rdx, rdx  {sub_0}
			48 31 c0                      //  xor     rax, rax  {sub_0}
			b0 02                         //  mov     al, 0x2
			48 c1 c8 28                   //  ror     rax, 0x28  {0x2000000}
			b0 61                         //  mov     al, 0x61
			49 89 c4                      //  mov     r12, rax  {0x2000061}
			0f 05                         //  syscall
			49 89 c1                      //  mov     r9, rax
			48 89 c7                      //  mov     rdi, rax
			48 31 f6                      //  xor     rsi, rsi  {sub_0}
			56                            //  push    rsi {var_8}  {sub_0}
			be 01 02 11 5c                //  mov     esi, 0x5c110201
			83 ee 01                      //  sub     esi, 0x1  {0x5c110200}
			56                            //  push    rsi {var_10}  {0x5c110200}
			48 89 e6                      //  mov     rsi, rsp {var_10}
			b2 10                         //  mov     dl, 0x10
			41 80 c4 07                   //  add     r12b, 0x7
			4c 89 e0                      //  mov     rax, r12  {0x2000068}
			0f 05                         //  syscall
			48 31 f6                      //  xor     rsi, rsi
			48 ff c6                      //  inc     rsi  {0x1}
			41 80 c4 02                   //  add     r12b, 0x2
			4c 89 e0                      //  mov     rax, r12  {0x200006a}
			0f 05                         //  syscall
			48 31 f6                      //  xor     rsi, rsi  {sub_0}
			41 80 ec 4c                   //  sub     r12b, 0x4c
			4c 89 e0                      //  mov     rax, r12  {0x200001e}
			0f 05                         //  syscall
			48 89 c7                      //  mov     rdi, rax
			48 31 f6                      //  xor     rsi, rsi  {sub_0}
			41 80 c4 3c                   //  add     r12b, 0x3c
			4c 89 e0                      //  mov     rax, r12  {0x200005a}
			0f 05                         //  syscall
			48 ff c6                      //  inc     rsi
			4c 89 e0                      //  mov     rax, r12  {0x200005a}
			0f 05                         //  syscall
			48 31 f6                      //  xor     rsi, rsi  {sub_0}
			56                            //  push    rsi {var_18}  {sub_0}
			48 bf 2f 2f 62 69 6e 2f 73 68 //  mov     rdi, 0x68732f6e69622f2f
			57                            //  push    rdi {var_20}  {0x68732f6e69622f2f}
			48 89 e7                      //  mov     rdi, rsp {var_20}
			48 31 d2                      //  xor     rdx, rdx  {sub_0}
			41 80 ec 1f                   //  sub     r12b, 0x1f  {0x3b}
			4c 89 e0                      //  mov     rax, r12  {0x200003b}
			0f 05                         //  syscall
		}

	condition:
		any of them
}

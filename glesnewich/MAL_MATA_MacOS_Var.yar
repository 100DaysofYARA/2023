rule MAL_MATA_SendPacket_Command_Opcodes
{
		meta:
			author = "Greg Lesnewich"
			date = "2023-01-18"
			version = "1.0"
			description = "check for Mata framework packet opcodes being moved into EDI before sending"

		strings:
			$0x20300 = { bf 00 03 02 00 31 f6 31 d2 e8 }
			$0x20600 = { bf 00 06 02 00 31 f6 49 89 d5 31 d2 e8 }
			$0x20500 = { bf 00 05 02 00 31 f6 31 d2 e8 }
			/*
				100005d7b  bf00050200         mov     edi, 0x20500
				100005d80  31f6               xor     esi, esi  {0x0}
				100005d82  31d2               xor     edx, edx  {0x0}
				100005d84  e867f9ffff         call    MataSendPacket
			*/
		condition:
			(uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
			all of them
}


rule MAL_MATA_Beacon_Command_Opcodes
{
		meta:
			author = "Greg Lesnewich"
			date = "2023-01-18"
			version = "1.0"
			description = "check for Mata framework beacon opcodes and handshake check"

		strings:
			$CMataNet_Auth = {
			c745c400000200     //1000012a2  c745c400000200     mov     dword [rbp-0x3c {var_44}], 0x20000
			488d75c4           //1000012a9  488d75c4           lea     rsi, [rbp-0x3c {var_44}]
			4c89f7             //1000012ad  4c89f7             mov     rdi, r14
			ba04000000         //1000012b0  ba04000000         mov     edx, 0x4
			b901000000         //1000012b5  b901000000         mov     ecx, 0x1
			e8????????         //1000012ba  e8????????         call    CMataNet_SendBlock
			85c0               //1000012bf  85c0               test    eax, eax
			74??               //1000012c1  74??               je      0x10000131b
			c745c400000000     //1000012c3  c745c400000000     mov     dword [rbp-0x3c {var_44}], 0x0
			488d75c4           //1000012ca  488d75c4           lea     rsi, [rbp-0x3c {var_44}]
			4c89f7             //1000012ce  4c89f7             mov     rdi, r14
			ba04000000         //1000012d1  ba04000000         mov     edx, 0x4
			b901000000         //1000012d6  b901000000         mov     ecx, 0x1
			41b82c010000       //1000012db  41b82c010000       mov     r8d, 0x12c
			e8????????         //1000012e1  e8????????         call    CMataNet_RecvBlock
			4531e4             //1000012e6  4531e4             xor     r12d, r12d  {0x0}
			85c0               //1000012e9  85c0               test    eax, eax
			74??               //1000012eb  74??               je      0x10000131e
			817dc400010200     //1000012ed  817dc400010200     cmp     dword [rbp-0x3c {var_44}], 0x20100
			75??   						 //1000012f4  75??               jne     0x10000131e
			c745c400020200     //1000012f6  c745c400020200     mov     dword [rbp-0x3c {var_44}], 0x20200
		}

		condition:
			(uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
			all of them
}

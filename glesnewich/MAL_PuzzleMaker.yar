rule MAL_PuzzleMaker_Launcher
{
    meta:
        description = "track the PuzzleMaker launcher based on its call to interact with the WMI namespace (CLSID_WbemLocator via CoCreateInstance)"
        author = "Greg Lesnewich"
        date = "2023-01-13"
        version = "1.0"
        reference = "https://securelist.com/puzzlemaker-chrome-zero-day-exploit-chain/102771/"
        hash = "982f7c4700c75b81833d5d59ad29147c392b20c760fe36b200b541a0f841c8a9"
        hash = "44d9f36c088dd420ad96a8518df7e9155145e04db788a99a8f8f99179427a447"
        hash = "bab8ad15015589e3f70643e6b59a5a37ab2c5a9cf799e0472cb9c1a29186babc"

	strings:
		$call_CoCreateInstance_WbemLocator = { 4? 89 6d bf 4? 8d 45 bf 4? 89 44 ?4 20 4? 8d 0d ?? ?? ?? ?? 33 d2 44 8d 42 01 4? 8d 0d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b d8 85 c0  }
        /*
           140001e9b  MOV        qword ptr [RBP + local_a0],R13
           140001e9f  LEA        RAX=>local_a0,[RBP + -0x41]
           140001ea3  MOV        qword ptr [RSP + local_e8],RAX
           140001ea8  LEA        R9,[DAT_1400164a8]                               = 87h
           140001eaf  XOR        param_2,param_2
           140001eb1  LEA        R8D,[param_2 + 0x1]
           140001eb5  LEA        param_1,[CLSID_WbemLocator]                      = 11
           140001ebc  CALL       qword ptr [->OLE32.DLL::CoCreateInstance]

        */
		$CreateService = { 4? 89 6c ?4 60 4? 8d 05 ?? ?? ?? ?? 4? 89 6c ?4 58 4? 8d 15 ?? ?? ?? ?? 4? 89 6c ?4 50 41 b9 ff 01 0f 00 4? 89 6c ?4 48 4? 8b cf 4? 89 6c ?4 40 4? 89 74 ?4 38 44 89 6c ?4 30 c7 44 ?4 28 02 00 00 00 c7 44 ?4 20 10 00 00 00 ff 15 }
        /*
           14000199f 4c 89 6c      MOV        qword ptr [RSP + local_5f8],R13
           1400019a4 4c 8d 05      LEA        R8,[DAT_14001e5d0]                               = 20h
           1400019ab 4c 89 6c      MOV        qword ptr [RSP + local_600],R13
           1400019b0 48 8d 15      LEA        RDX,[DAT_140021e98]                              = 0095h
           1400019b7 4c 89 6c      MOV        qword ptr [RSP + local_608],R13
           1400019bc 41 b9 ff      MOV        R9D,0xf01ff
           1400019c2 4c 89 6c      MOV        qword ptr [RSP + local_610],R13
           1400019c7 48 8b cf      MOV        RCX,RDI
           1400019ca 4c 89 6c      MOV        qword ptr [RSP + local_618],R13
           1400019cf 48 89 74      MOV        qword ptr [RSP + local_620],RSI=>DAT_140021c90   = 00A1h
           1400019d4 44 89 6c      MOV        dword ptr [RSP + local_628],R13D
           1400019d9 c7 44 24      MOV        dword ptr [RSP + local_630],0x2
           1400019e1 c7 44 24      MOV        dword ptr [RSP + local_638],0x10
           1400019e9 ff 15 19      CALL       qword ptr [->ADVAPI32.DLL::CreateServiceW]

        */
	condition:
		uint16be(0x0) == 0x4d5a and
        1 of them
}


rule MAL_PuzzleMaker_Payload
{
    meta:
        description = "track the PuzzleMaker payload based on some cryptography API calls and a subroutine in a case (maybe a command?) statement"
        author = "Greg Lesnewich"
        date = "2023-01-13"
        version = "1.0"
        reference = "https://securelist.com/puzzlemaker-chrome-zero-day-exploit-chain/102771/"
        hash = "2ae29e697c516dc79c6fbf68f951a5f592f151abd81ed943c2fdd225c5d4d391"
        hash = "8a17279ba26c8fbe6966ea3300fdefb1adae1b3ed68f76a7fc81413bd8c1a5f6"
        hash = "f2ce2a00de8673f52d37911f3e0752b8dfab751b2a17e719a565b4083455528e"

	strings:
		$case_statement = { 33 db 4? 8d 4? ?? 80 7? 00 01 8b fb 41 8b d4 4? 8b ce 40 0f 94 ?? 41 80 f9 15 89 7c ?4 20 0f 94 ?? 44 8b cb  }
        /*
            switchD_180001fd4::caseD_15
           180001fe7  XOR        EBX,EBX
           180001fe9  LEA        R8,[RBP + 0x1]
           180001fed  CMP        byte ptr [RBP],0x1
           180001ff1  MOV        EDI,EBX
           180001ff3  MOV        param_2,R12D
           180001ff6  MOV        param_1,RSI
           180001ff9  SETZ       DIL
           180001ffd  CMP        R9B,0x15
           180002001  MOV        dword ptr [RSP + local_f8],EDI
           180002005  SETZ       BL
           180002008  MOV        R9D,EBX
           18000200b  CALL       mw_open_pipe_create_proc                         undefined mw_open_pipe_create_pr

        */

		$cryptography = { 41 b9 01 00 00 00 c7 44 ?4 20 00 00 00 f0 45 33 c0 4? 8d 4c ?4 60 33 d2 ff 15 ?? ?? ?? ?? 85 c0 74 ?? 4? 8b 4c ?4 60 4? 8d 85 b0 00 00 00 ba 20 00 00 00 ff 15 ?? ?? ?? ?? 4? 8b 4c ?4 60 33 d2  }
        /*
           1800040d1  MOV        R9D,0x1
           1800040d7  MOV        dword ptr [RSP + local_9e8],0xf0000000
           1800040df  XOR        param_3,param_3
           1800040e2  LEA        param_1=>local_9b8,[RSP + 0x50]
           1800040e7  XOR        param_2,param_2
           1800040e9  CALL       qword ptr [->ADVAPI32.DLL::CryptAcquireContextW]
           1800040ef  TEST       EAX,EAX
           1800040f1  JZ         LAB_18000411b
           1800040f3  MOV        param_1=>local_9b8,qword ptr [RSP + 0x50]
           1800040f8  LEA        param_3=>local_868,[RBP + 0xa0]
           1800040ff  MOV        param_2,0x20
           180004104  CALL       qword ptr [->ADVAPI32.DLL::CryptGenRandom]
           18000410a  MOV        param_1,qword ptr [RSP + local_9b8]
           18000410f  XOR        param_2,param_2
           180004111  TEST       EAX,EAX
           180004113  JNZ        LAB_180004125
           180004115  CALL       qword ptr [->ADVAPI32.DLL::CryptReleaseContext]

        */

	condition:
		uint16be(0x0) == 0x4d5a and
        1 of them
}

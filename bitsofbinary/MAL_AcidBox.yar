/*
Collection of rules to cover the AcidBox malware framework as described in the following blog:
https://unit42.paloaltonetworks.com/acidbox-rare-malware/
*/

rule AcidBox_SSP_DLL_Loader_Format_Strings {
    meta:
        description = "Detects AcidBox SSP DLL loaders, based on a combination of format strings"
        author = "BitsOfBinary"
        reference = "https://unit42.paloaltonetworks.com/acidbox-rare-malware/"
        reference = "https://bitsofbinary.github.io/yara/2023/03/19/100daysofyara-day-78.html"
        hash = "003669761229d3e1db0f5a5b333ef62b3dffcc8e27c821ce9018362e0a2df7e9"
        version = "1.0"
        date = "2023-03-19"
        DaysofYARA = "78/100"
        
    strings:
        $ = "%s\\%s"
        $ = "%s\\%s{%s}"
        $ = "s\\{%s}"
        
    condition:
        all of them
}

rule AcidBox_SSP_DLL_Loader_Format_String_Chunk {
    meta:
        description = "Detects AcidBox SSP DLL loaders, based on a unique string chunk of format strings"
        author = "BitsOfBinary"
        reference = "https://unit42.paloaltonetworks.com/acidbox-rare-malware/"
        hash = "003669761229d3e1db0f5a5b333ef62b3dffcc8e27c821ce9018362e0a2df7e9"
        version = "1.0"
        date = "2023-03-20"
        DaysofYARA = "79/100"
        
    strings:
        // %s\%s
        // %s\%s{%s}
        // s\{%s}
        $ = {25 73 5C 25 73 00 00 00 00 00 00 00 25 73 5C 25 73 7B 25 73 7D 00 00 00 00 00 00 00 25 73 5C 7B 25 73 7D 00}
        
    condition:
        any of them
}

rule AcidBox_SSP_DLL_Loader_Format_String_Combos {
    meta:
        description = "Detects AcidBox SSP DLL loaders, based on combinations of format strings seen in samples"
        author = "BitsOfBinary"
        reference = "https://unit42.paloaltonetworks.com/acidbox-rare-malware/"
        reference = "https://bitsofbinary.github.io/yara/2023/03/21/100daysofyara-day-80.html"
        hash = "003669761229d3e1db0f5a5b333ef62b3dffcc8e27c821ce9018362e0a2df7e9"
        version = "1.0"
        date = "2023-03-21"
        DaysofYARA = "80/100"
        
    strings:
        // Combinations of the following (with alignment bytes):
        // %s\%s
        // %s\%s{%s}
        // s\{%s}
        $ = {25 73 5C 25 73 00 00 00 00 00 00 00 25 73 5C 25 73 7B 25 73 7D 00}
        $ = {25 73 5C 25 73 00 00 00 00 00 00 00 25 73 5C 7B 25 73 7D 00}
        $ = {25 73 5C 25 73 7B 25 73 7D 00 00 00 00 00 00 00 25 73 5C 25 73 00}
        $ = {25 73 5C 25 73 7B 25 73 7D 00 00 00 00 00 00 00 25 73 5C 7B 25 73 7D 00}
        $ = {25 73 5C 7B 25 73 7D 00 00 00 00 00 00 00 25 73 5C 25 73 00}
        $ = {25 73 5C 7B 25 73 7D 00 00 00 00 00 00 00 25 73 5C 25 73 7B 25 73 7D 00}
        
    condition:
        any of them
}

rule AcidBox_SSP_DLL_Loader_Format_String_Combos_Loose {
    meta:
        description = "Detects AcidBox SSP DLL loaders, based on combinations of format strings seen in samples. This rule uses a looser set of strings, so may be more false positive-prone."
        author = "BitsOfBinary"
        reference = "https://unit42.paloaltonetworks.com/acidbox-rare-malware/"
        reference = "https://bitsofbinary.github.io/yara/2023/03/22/100daysofyara-day-81.html"
        hash = "003669761229d3e1db0f5a5b333ef62b3dffcc8e27c821ce9018362e0a2df7e9"
        version = "1.0"
        date = "2023-03-22"
        DaysofYARA = "81/100"
        
    strings:
        // Combinations of the following (with alignment bytes):
        // %s\%s
        // %s\%s{%s}
        // s\{%s}
        $ = {25 73 5C 25 73 00 [0-16] 25 73 5C 25 73 7B 25 73 7D 00}
        $ = {25 73 5C 25 73 00 [0-16] 25 73 5C 7B 25 73 7D 00}
        $ = {25 73 5C 25 73 7B 25 73 7D 00 [0-16] 25 73 5C 25 73 00}
        $ = {25 73 5C 25 73 7B 25 73 7D 00 [0-16] 25 73 5C 7B 25 73 7D 00}
        $ = {25 73 5C 7B 25 73 7D 00 [0-16] 25 73 5C 25 73 00}
        $ = {25 73 5C 7B 25 73 7D 00 [0-16] 25 73 5C 25 73 7B 25 73 7D 00}
        
    condition:
        any of them
}

import "pe"
import "hash"

rule AcidBox_SSP_DLL_Loader_Imphash {
    meta:
        description = "Detects AcidBox SSP DLL loaders, based on a unique import hash"
        author = "BitsOfBinary"
        reference = "https://unit42.paloaltonetworks.com/acidbox-rare-malware/"
        reference = "https://bitsofbinary.github.io/yara/2023/03/23/100daysofyara-day-82.html"
        hash = "003669761229d3e1db0f5a5b333ef62b3dffcc8e27c821ce9018362e0a2df7e9"
        version = "1.0"
        date = "2023-03-23"
        DaysofYARA = "82/100"

    condition:
        pe.imphash() == "30851d4a2b31e9699084a06e765e21b0"
}

import "pe"
import "hash"

rule AcidBox_SSP_DLL_Loader_Rich_Header_Hash {
    meta:
        description = "Detects AcidBox SSP DLL loaders, based on a unique rich header hash"
        author = "BitsOfBinary"
        reference = "https://unit42.paloaltonetworks.com/acidbox-rare-malware/"
        reference = "https://bitsofbinary.github.io/yara/2023/03/23/100daysofyara-day-82.html"
        hash = "003669761229d3e1db0f5a5b333ef62b3dffcc8e27c821ce9018362e0a2df7e9"
        version = "1.0"
        date = "2023-03-23"
        DaysofYARA = "82/100"

    condition:
        hash.md5(pe.rich_signature.clear_data) == "269af2751efee65b1ab00622816c83e6"
}

import "pe"

rule AcidBox_SSP_DLL_Loader_windigest_Version_Info {
    meta:
        description = "Detects AcidBox SSP DLL loaders, based on a unique version information of 'windigest' and a description"
        author = "BitsOfBinary"
        reference = "https://unit42.paloaltonetworks.com/acidbox-rare-malware/"
        reference = "https://bitsofbinary.github.io/yara/2023/03/24/100daysofyara-day-83.html"
        hash = "003669761229d3e1db0f5a5b333ef62b3dffcc8e27c821ce9018362e0a2df7e9"
        version = "1.0"
        date = "2023-03-24"
        DaysofYARA = "83/100"
        
    condition:
        pe.version_info["InternalName"] == "windigest.dll" or
        pe.version_info["FileDescription"] == "Windows Digest Access"
}

import "pe"

rule AcidBox_SSP_DLL_Loader_msv1_1_Version_Info {
    meta:
        description = "Detects AcidBox SSP DLL loaders, based on a unique version information of 'msv1_1'"
        author = "BitsOfBinary"
        reference = "https://unit42.paloaltonetworks.com/acidbox-rare-malware/"
        reference = "https://bitsofbinary.github.io/yara/2023/03/25/100daysofyara-day-84.html"
        version = "1.0"
        date = "2023-03-24"
        DaysofYARA = "84/100"
        
    condition:
        pe.version_info["InternalName"] == "msv1_1.dll"
}

import "pe"

rule AcidBox_SSP_DLL_Loader_pku_Version_Info {
    meta:
        description = "Detects AcidBox SSP DLL loaders, based on a unique version information of 'pku.dll'"
        author = "BitsOfBinary"
        reference = "https://unit42.paloaltonetworks.com/acidbox-rare-malware/"
        reference = "https://bitsofbinary.github.io/yara/2023/03/25/100daysofyara-day-84.html"
        version = "1.0"
        date = "2023-03-24"
        DaysofYARA = "84/100"
        
    condition:
        pe.version_info["InternalName"] == "pku.dll"
}

import "pe"

rule AcidBox_SSP_DLL_Loader_Unique_Exports {
    meta:
        description = "Detects AcidBox SSP DLL loaders, based on having unique exported functions"
        author = "BitsOfBinary"
        reference = "https://unit42.paloaltonetworks.com/acidbox-rare-malware/"
        reference = "https://bitsofbinary.github.io/yara/2023/03/26/100daysofyara-day-85.html"
        hash = "003669761229d3e1db0f5a5b333ef62b3dffcc8e27c821ce9018362e0a2df7e9"
        version = "1.0"
        date = "2023-03-26"
        DaysofYARA = "85/100"
        
    condition:
        pe.exports("InitPhysicalInterfaceA") or
        pe.exports("UpdateSecurityContext")
}

rule AcidBox_SSP_DLL_Loader_Unique_Exports_Strings {
    meta:
        description = "Detects the strings of unique exported functions of AcidBox SSP DLL loaders"
        author = "BitsOfBinary"
        reference = "https://unit42.paloaltonetworks.com/acidbox-rare-malware/"
        reference = "https://bitsofbinary.github.io/yara/2023/03/26/100daysofyara-day-85.html"
        hash = "003669761229d3e1db0f5a5b333ef62b3dffcc8e27c821ce9018362e0a2df7e9"
        version = "1.0"
        date = "2023-03-26"
        DaysofYARA = "85/100"
        
    strings:
        $ = "InitPhysicalInterfaceA"
        $ = "UpdateSecurityContext"
        
    condition:
        any of them
}

rule AcidBox_SSP_DLL_Loader_Crypto_Routine_A {
    meta:
        description = "Detects AcidBox SSP DLL loaders, based on a unique cryptography routine"
        author = "BitsOfBinary"
        reference = "https://unit42.paloaltonetworks.com/acidbox-rare-malware/"
        reference = "https://bitsofbinary.github.io/yara/2023/03/28/100daysofyara-day-87.html"
        hash = "003669761229d3e1db0f5a5b333ef62b3dffcc8e27c821ce9018362e0a2df7e9"
        version = "1.0"
        date = "2023-03-28"
        DaysofYARA = "87/100"
        
    strings:
        // 180013a71 0f  b6  04  32   MOVZX      EAX ,byte ptr [param_2  + RSI *0x1 ]
        // 180013a75 33  c8           XOR        param_1 ,EAX
        // 180013a77 88  0c  3a       MOV        byte ptr [param_2  + RDI *0x1 ],param_1
        // 180013a7a 41  ff  c0       INC        param_3
        // 180013a7d 44  89  44       MOV        dword ptr [RSP  + local_14 ],param_3
        //           24  04
        $ = {0f b6 04 32 33 c8 88 0c 3a 41 ff c0 44 89 44 24 04}
        
    condition:
        any of them
}

rule AcidBox_SSP_DLL_Loader_Crypto_Routine_B {
    meta:
        description = "Detects AcidBox SSP DLL loaders, based on a unique cryptography routine"
        author = "BitsOfBinary"
        reference = "https://unit42.paloaltonetworks.com/acidbox-rare-malware/"
        reference = "https://bitsofbinary.github.io/yara/2023/03/29/100daysofyara-day-88.html"
        hash = "003669761229d3e1db0f5a5b333ef62b3dffcc8e27c821ce9018362e0a2df7e9"
        version = "1.0"
        date = "2023-03-29"
        DaysofYARA = "88/100"
        
    strings:
        // 180013a71 0f  b6  04  32   MOVZX      EAX ,byte ptr [param_2  + RSI *0x1 ]
        // 180013a75 33  c8           XOR        param_1 ,EAX
        // 180013a77 88  0c  3a       MOV        byte ptr [param_2  + RDI *0x1 ],param_1
        // 180013a7a 41  ff  c0       INC        param_3
        // 180013a7d 44  89  44       MOV        dword ptr [RSP  + local_14 ],param_3
        //           24  04
        $ = {0f b6 04 32 33 c8 88 0c 3a 4? ff c0 4? 89 44 ?4 04}
        
    condition:
        any of them
}

rule AcidBox_SSP_DLL_Loader_Crypto_Routine_C {
    meta:
        description = "Detects AcidBox SSP DLL loaders, based on a unique cryptography routine"
        author = "BitsOfBinary"
        reference = "https://unit42.paloaltonetworks.com/acidbox-rare-malware/"
        reference = "https://bitsofbinary.github.io/yara/2023/03/30/100daysofyara-day-89.html"
        hash = "003669761229d3e1db0f5a5b333ef62b3dffcc8e27c821ce9018362e0a2df7e9"
        version = "1.0"
        date = "2023-03-30"
        DaysofYARA = "89/100"
        
    strings:
        // 180013a71 0f  b6  04  32   MOVZX      EAX ,byte ptr [param_2  + RSI *0x1 ]
        // 180013a75 33  c8           XOR        param_1 ,EAX
        // 180013a77 88  0c  3a       MOV        byte ptr [param_2  + RDI *0x1 ],param_1
        // 180013a7a 41  ff  c0       INC        param_3
        // 180013a7d 44  89  44       MOV        dword ptr [RSP  + local_14 ],param_3
        //           24  04
        $ = {0f b6 04 32 33 c8 88 0c 3a 4? ff c? 4? 89}
        
    condition:
        any of them
}

rule AcidBox_SSP_DLL_Loader_Unique_Return_Codes_A {
    meta:
        description = "Detects AcidBox SSP DLL loaders, based on unique return codes seen in functions"
        author = "BitsOfBinary"
        reference = "https://unit42.paloaltonetworks.com/acidbox-rare-malware/"
        reference = "https://bitsofbinary.github.io/yara/2023/04/01/100daysofyara-day-91.html"
        hash = "003669761229d3e1db0f5a5b333ef62b3dffcc8e27c821ce9018362e0a2df7e9"
        version = "1.0"
        date = "2023-04-01"
        DaysofYARA = "91/100"
        
    strings:
        $ = {06 04 00 a0}
        $ = {01 04 00 a0}
        $ = {02 04 00 a0}
        $ = {0c 0c 00 a0}
        $ = {02 0c 00 a0}
        $ = {01 07 00 a0}
        $ = {07 08 00 a0}
        $ = {02 07 00 a0}
        $ = {04 06 00 a0}
        $ = {08 06 00 a0}
        $ = {02 06 00 a0}
        $ = {0c 08 00 a0}
        $ = {06 08 00 a0}
        $ = {04 08 00 a0}
        $ = {07 10 03 a0}
        $ = {09 10 03 a0}
        $ = {11 10 03 a0}
        $ = {02 10 03 a0}
        $ = {04 04 08 a0}
        $ = {07 04 08 a0}
        $ = {02 03 00 a0}
        $ = {02 04 08 a0}
        $ = {04 01 08 a0}
        $ = {06 01 08 a0}
        $ = {0e 01 08 a0}
        $ = {01 02 08 a0}
        $ = {02 02 08 a0}
        $ = {04 02 08 a0}
        $ = {06 02 08 a0}
        $ = {01 00 00 c0}
        $ = {02 0a 08 a0}
        $ = {02 06 03 a0}
        $ = {04 06 03 a0}
        $ = {10 06 03 a0}
        $ = {0e 06 03 a0}
        $ = {02 08 02 80}
        $ = {06 08 02 80}
        $ = {01 08 02 80}
        $ = {04 08 02 80}
        $ = {07 08 02 80}
        $ = {71 80 07 80}
        $ = {06 01 03 80}
        $ = {02 01 03 80}
        $ = {02 06 03 80}
        $ = {01 06 03 80}
        $ = {02 07 03 80}
        $ = {06 07 03 80}
        $ = {07 06 04 80}
        $ = {04 06 04 80}
        $ = {05 06 04 80}
        $ = {02 06 04 80}
        $ = {07 16 04 80}
        $ = {04 16 04 80}
        $ = {06 16 04 80}
        $ = {02 16 04 80}
        $ = {02 28 04 80}
        $ = {07 28 04 80}
        $ = {06 0b 04 80}
        $ = {02 0b 04 80}
        $ = {02 0c 04 80}
        $ = {02 0d 04 80}
        $ = {06 0d 04 80}
        $ = {02 1c 04 80}
        $ = {04 1c 04 80}
        $ = {07 1c 04 80}
        $ = {06 1c 04 80}
        $ = {0c 1c 04 80}
        $ = {06 1d 04 80}
        $ = {09 22 04 80}
        $ = {09 08 04 80}
        $ = {09 09 04 80}
        $ = {09 07 04 80}
        $ = {02 22 04 80}
        $ = {0c 01 04 80}
        $ = {02 01 04 80}
        $ = {02 10 04 80}
        $ = {02 11 04 80}
        $ = {07 11 04 80}
        $ = {0a 11 04 80}
        $ = {02 12 04 80}
        $ = {0a 12 04 80}
        $ = {07 12 04 80}
        $ = {01 0f 04 80}
        $ = {07 0f 04 80}
        $ = {02 0f 04 80}
        $ = {0a 0f 04 80}
        $ = {0b 0f 04 80}
        $ = {02 02 04 80}
        $ = {07 04 04 80}
        $ = {0c 04 04 80}
        $ = {02 04 04 80}
        $ = {02 14 04 80}
        $ = {02 15 04 80}
        $ = {0a 14 04 80}
        $ = {07 15 04 80}
        $ = {0c 15 04 80}
        $ = {09 25 04 80}
        $ = {02 25 04 80}
        $ = {02 26 04 80}
        $ = {06 27 04 80}
        $ = {07 27 04 80}
        $ = {09 27 04 80}
        $ = {0c 27 04 80}
        $ = {0a 27 04 80}
        $ = {04 27 04 80}
        $ = {02 27 04 80}
        $ = {04 13 04 80}
        $ = {0c 13 04 80}
        $ = {06 13 04 80}
        $ = {01 13 04 80}
        $ = {02 13 04 80}
        $ = {0c 21 04 80}
        $ = {06 21 04 80}
        $ = {05 21 04 80}
        $ = {02 21 04 80}
        $ = {06 17 04 80}
        $ = {0c 17 04 80}
        $ = {02 17 04 80}
        $ = {02 05 05 80}
        $ = {06 05 05 80}
        $ = {06 07 05 80}
        $ = {04 07 05 80}
        $ = {02 07 05 80}
        $ = {02 09 05 80}
        $ = {06 09 05 80}
        $ = {01 0b 07 80}
        $ = {06 0b 07 80}
        $ = {02 0b 07 80}
        $ = {06 0c 07 80}
        $ = {02 0c 07 80}
        $ = {05 03 01 80}
        $ = {02 03 01 80}
        
    condition:
        uint16(0) == 0x5A4D and filesize < 500KB and 80 of them
}

import "pe"

rule AcidBox_SSP_DLL_Loader_Unique_Return_Codes_B {
    meta:
        description = "Detects AcidBox SSP DLL loaders, based on unique return codes seen in functions"
        author = "BitsOfBinary"
        reference = "https://unit42.paloaltonetworks.com/acidbox-rare-malware/"
        reference = "https://bitsofbinary.github.io/yara/2023/04/02/100daysofyara-day-92.html"
        hash = "003669761229d3e1db0f5a5b333ef62b3dffcc8e27c821ce9018362e0a2df7e9"
        version = "1.0"
        date = "2023-04-02"
        DaysofYARA = "92/100"
        
    strings:
        $ = {06 04 00 a0}
        $ = {01 04 00 a0}
        $ = {02 04 00 a0}
        $ = {0c 0c 00 a0}
        $ = {02 0c 00 a0}
        $ = {01 07 00 a0}
        $ = {07 08 00 a0}
        $ = {02 07 00 a0}
        $ = {04 06 00 a0}
        $ = {08 06 00 a0}
        $ = {02 06 00 a0}
        $ = {0c 08 00 a0}
        $ = {06 08 00 a0}
        $ = {04 08 00 a0}
        $ = {07 10 03 a0}
        $ = {09 10 03 a0}
        $ = {11 10 03 a0}
        $ = {02 10 03 a0}
        $ = {04 04 08 a0}
        $ = {07 04 08 a0}
        $ = {02 03 00 a0}
        $ = {02 04 08 a0}
        $ = {04 01 08 a0}
        $ = {06 01 08 a0}
        $ = {0e 01 08 a0}
        $ = {01 02 08 a0}
        $ = {02 02 08 a0}
        $ = {04 02 08 a0}
        $ = {06 02 08 a0}
        $ = {01 00 00 c0}
        $ = {02 0a 08 a0}
        $ = {02 06 03 a0}
        $ = {04 06 03 a0}
        $ = {10 06 03 a0}
        $ = {0e 06 03 a0}
        $ = {02 08 02 80}
        $ = {06 08 02 80}
        $ = {01 08 02 80}
        $ = {04 08 02 80}
        $ = {07 08 02 80}
        $ = {71 80 07 80}
        $ = {06 01 03 80}
        $ = {02 01 03 80}
        $ = {02 06 03 80}
        $ = {01 06 03 80}
        $ = {02 07 03 80}
        $ = {06 07 03 80}
        $ = {07 06 04 80}
        $ = {04 06 04 80}
        $ = {05 06 04 80}
        $ = {02 06 04 80}
        $ = {07 16 04 80}
        $ = {04 16 04 80}
        $ = {06 16 04 80}
        $ = {02 16 04 80}
        $ = {02 28 04 80}
        $ = {07 28 04 80}
        $ = {06 0b 04 80}
        $ = {02 0b 04 80}
        $ = {02 0c 04 80}
        $ = {02 0d 04 80}
        $ = {06 0d 04 80}
        $ = {02 1c 04 80}
        $ = {04 1c 04 80}
        $ = {07 1c 04 80}
        $ = {06 1c 04 80}
        $ = {0c 1c 04 80}
        $ = {06 1d 04 80}
        $ = {09 22 04 80}
        $ = {09 08 04 80}
        $ = {09 09 04 80}
        $ = {09 07 04 80}
        $ = {02 22 04 80}
        $ = {0c 01 04 80}
        $ = {02 01 04 80}
        $ = {02 10 04 80}
        $ = {02 11 04 80}
        $ = {07 11 04 80}
        $ = {0a 11 04 80}
        $ = {02 12 04 80}
        $ = {0a 12 04 80}
        $ = {07 12 04 80}
        $ = {01 0f 04 80}
        $ = {07 0f 04 80}
        $ = {02 0f 04 80}
        $ = {0a 0f 04 80}
        $ = {0b 0f 04 80}
        $ = {02 02 04 80}
        $ = {07 04 04 80}
        $ = {0c 04 04 80}
        $ = {02 04 04 80}
        $ = {02 14 04 80}
        $ = {02 15 04 80}
        $ = {0a 14 04 80}
        $ = {07 15 04 80}
        $ = {0c 15 04 80}
        $ = {09 25 04 80}
        $ = {02 25 04 80}
        $ = {02 26 04 80}
        $ = {06 27 04 80}
        $ = {07 27 04 80}
        $ = {09 27 04 80}
        $ = {0c 27 04 80}
        $ = {0a 27 04 80}
        $ = {04 27 04 80}
        $ = {02 27 04 80}
        $ = {04 13 04 80}
        $ = {0c 13 04 80}
        $ = {06 13 04 80}
        $ = {01 13 04 80}
        $ = {02 13 04 80}
        $ = {0c 21 04 80}
        $ = {06 21 04 80}
        $ = {05 21 04 80}
        $ = {02 21 04 80}
        $ = {06 17 04 80}
        $ = {0c 17 04 80}
        $ = {02 17 04 80}
        $ = {02 05 05 80}
        $ = {06 05 05 80}
        $ = {06 07 05 80}
        $ = {04 07 05 80}
        $ = {02 07 05 80}
        $ = {02 09 05 80}
        $ = {06 09 05 80}
        $ = {01 0b 07 80}
        $ = {06 0b 07 80}
        $ = {02 0b 07 80}
        $ = {06 0c 07 80}
        $ = {02 0c 07 80}
        $ = {05 03 01 80}
        $ = {02 03 01 80}
        
    condition:
        uint16(0) == 0x5A4D and filesize < 500KB and 30 of them and not for any of them : (
            not $ in (pe.sections[0].raw_data_offset .. pe.sections[0].raw_data_offset + pe.sections[0].raw_data_size) and
            # > 3
        )
}

rule AcidBox_SSP_DLL_Loader_Unique_Return_Codes_C {
    meta:
        description = "Detects AcidBox SSP DLL loaders, based on unique return codes seen in functions"
        author = "BitsOfBinary"
        reference = "https://unit42.paloaltonetworks.com/acidbox-rare-malware/"
        reference = "https://bitsofbinary.github.io/yara/2023/04/03/100daysofyara-day-93.html"
        hash = "003669761229d3e1db0f5a5b333ef62b3dffcc8e27c821ce9018362e0a2df7e9"
        version = "1.0"
        date = "2023-04-03"
        DaysofYARA = "93/100"
        
    strings:
        $ = {(b8|bb) 06 04 00 a0}
        $ = {(b8|bb) 01 04 00 a0}
        $ = {(b8|bb) 02 04 00 a0}
        $ = {(b8|bb) 0c 0c 00 a0}
        $ = {(b8|bb) 02 0c 00 a0}
        $ = {(b8|bb) 01 07 00 a0}
        $ = {(b8|bb) 07 08 00 a0}
        $ = {(b8|bb) 02 07 00 a0}
        $ = {(b8|bb) 04 06 00 a0}
        $ = {(b8|bb) 08 06 00 a0}
        $ = {(b8|bb) 02 06 00 a0}
        $ = {(b8|bb) 0c 08 00 a0}
        $ = {(b8|bb) 06 08 00 a0}
        $ = {(b8|bb) 04 08 00 a0}
        $ = {(b8|bb) 07 10 03 a0}
        $ = {(b8|bb) 09 10 03 a0}
        $ = {(b8|bb) 11 10 03 a0}
        $ = {(b8|bb) 02 10 03 a0}
        $ = {(b8|bb) 04 04 08 a0}
        $ = {(b8|bb) 07 04 08 a0}
        $ = {(b8|bb) 02 03 00 a0}
        $ = {(b8|bb) 02 04 08 a0}
        $ = {(b8|bb) 04 01 08 a0}
        $ = {(b8|bb) 06 01 08 a0}
        $ = {(b8|bb) 0e 01 08 a0}
        $ = {(b8|bb) 01 02 08 a0}
        $ = {(b8|bb) 02 02 08 a0}
        $ = {(b8|bb) 04 02 08 a0}
        $ = {(b8|bb) 06 02 08 a0}
        $ = {(b8|bb) 01 00 00 c0}
        $ = {(b8|bb) 02 0a 08 a0}
        $ = {(b8|bb) 02 06 03 a0}
        $ = {(b8|bb) 04 06 03 a0}
        $ = {(b8|bb) 10 06 03 a0}
        $ = {(b8|bb) 0e 06 03 a0}
        $ = {(b8|bb) 02 08 02 80}
        $ = {(b8|bb) 06 08 02 80}
        $ = {(b8|bb) 01 08 02 80}
        $ = {(b8|bb) 04 08 02 80}
        $ = {(b8|bb) 07 08 02 80}
        $ = {(b8|bb) 71 80 07 80}
        $ = {(b8|bb) 06 01 03 80}
        $ = {(b8|bb) 02 01 03 80}
        $ = {(b8|bb) 02 06 03 80}
        $ = {(b8|bb) 01 06 03 80}
        $ = {(b8|bb) 02 07 03 80}
        $ = {(b8|bb) 06 07 03 80}
        $ = {(b8|bb) 07 06 04 80}
        $ = {(b8|bb) 04 06 04 80}
        $ = {(b8|bb) 05 06 04 80}
        $ = {(b8|bb) 02 06 04 80}
        $ = {(b8|bb) 07 16 04 80}
        $ = {(b8|bb) 04 16 04 80}
        $ = {(b8|bb) 06 16 04 80}
        $ = {(b8|bb) 02 16 04 80}
        $ = {(b8|bb) 02 28 04 80}
        $ = {(b8|bb) 07 28 04 80}
        $ = {(b8|bb) 06 0b 04 80}
        $ = {(b8|bb) 02 0b 04 80}
        $ = {(b8|bb) 02 0c 04 80}
        $ = {(b8|bb) 02 0d 04 80}
        $ = {(b8|bb) 06 0d 04 80}
        $ = {(b8|bb) 02 1c 04 80}
        $ = {(b8|bb) 04 1c 04 80}
        $ = {(b8|bb) 07 1c 04 80}
        $ = {(b8|bb) 06 1c 04 80}
        $ = {(b8|bb) 0c 1c 04 80}
        $ = {(b8|bb) 06 1d 04 80}
        $ = {(b8|bb) 09 22 04 80}
        $ = {(b8|bb) 09 08 04 80}
        $ = {(b8|bb) 09 09 04 80}
        $ = {(b8|bb) 09 07 04 80}
        $ = {(b8|bb) 02 22 04 80}
        $ = {(b8|bb) 0c 01 04 80}
        $ = {(b8|bb) 02 01 04 80}
        $ = {(b8|bb) 02 10 04 80}
        $ = {(b8|bb) 02 11 04 80}
        $ = {(b8|bb) 07 11 04 80}
        $ = {(b8|bb) 0a 11 04 80}
        $ = {(b8|bb) 02 12 04 80}
        $ = {(b8|bb) 0a 12 04 80}
        $ = {(b8|bb) 07 12 04 80}
        $ = {(b8|bb) 01 0f 04 80}
        $ = {(b8|bb) 07 0f 04 80}
        $ = {(b8|bb) 02 0f 04 80}
        $ = {(b8|bb) 0a 0f 04 80}
        $ = {(b8|bb) 0b 0f 04 80}
        $ = {(b8|bb) 02 02 04 80}
        $ = {(b8|bb) 07 04 04 80}
        $ = {(b8|bb) 0c 04 04 80}
        $ = {(b8|bb) 02 04 04 80}
        $ = {(b8|bb) 02 14 04 80}
        $ = {(b8|bb) 02 15 04 80}
        $ = {(b8|bb) 0a 14 04 80}
        $ = {(b8|bb) 07 15 04 80}
        $ = {(b8|bb) 0c 15 04 80}
        $ = {(b8|bb) 09 25 04 80}
        $ = {(b8|bb) 02 25 04 80}
        $ = {(b8|bb) 02 26 04 80}
        $ = {(b8|bb) 06 27 04 80}
        $ = {(b8|bb) 07 27 04 80}
        $ = {(b8|bb) 09 27 04 80}
        $ = {(b8|bb) 0c 27 04 80}
        $ = {(b8|bb) 0a 27 04 80}
        $ = {(b8|bb) 04 27 04 80}
        $ = {(b8|bb) 02 27 04 80}
        $ = {(b8|bb) 04 13 04 80}
        $ = {(b8|bb) 0c 13 04 80}
        $ = {(b8|bb) 06 13 04 80}
        $ = {(b8|bb) 01 13 04 80}
        $ = {(b8|bb) 02 13 04 80}
        $ = {(b8|bb) 0c 21 04 80}
        $ = {(b8|bb) 06 21 04 80}
        $ = {(b8|bb) 05 21 04 80}
        $ = {(b8|bb) 02 21 04 80}
        $ = {(b8|bb) 06 17 04 80}
        $ = {(b8|bb) 0c 17 04 80}
        $ = {(b8|bb) 02 17 04 80}
        $ = {(b8|bb) 02 05 05 80}
        $ = {(b8|bb) 06 05 05 80}
        $ = {(b8|bb) 06 07 05 80}
        $ = {(b8|bb) 04 07 05 80}
        $ = {(b8|bb) 02 07 05 80}
        $ = {(b8|bb) 02 09 05 80}
        $ = {(b8|bb) 06 09 05 80}
        $ = {(b8|bb) 01 0b 07 80}
        $ = {(b8|bb) 06 0b 07 80}
        $ = {(b8|bb) 02 0b 07 80}
        $ = {(b8|bb) 06 0c 07 80}
        $ = {(b8|bb) 02 0c 07 80}
        $ = {(b8|bb) 05 03 01 80}
        $ = {(b8|bb) 02 03 01 80}
        
    condition:
        uint16(0) == 0x5A4D and 10 of them
}

rule Heuristic_Stack_String_SeLoadDriverPrivilege_A {
    meta:
        description = "Detects the stack string SeLoadDriverPrivilege being loaded in a combination of 1, 2, and 4 byte chunks, not necessarily in order"
        author = "BitsOfBinary"
        reference = "https://bitsofbinary.github.io/yara/2023/04/06/100daysofyara-day-96.html"
        version = "1.0"
        date = "2023-04-06"
        DaysofYARA = "96/100"

    strings:
        $one_byte_mov_S_stack = {C6 44 24 ?? 53}
        $one_byte_mov_e_stack = {C6 44 24 ?? 65}
        $one_byte_mov_L_stack = {C6 44 24 ?? 4c}
        $one_byte_mov_o_stack = {C6 44 24 ?? 6f}
        $one_byte_mov_a_stack = {C6 44 24 ?? 61}
        $one_byte_mov_d_stack = {C6 44 24 ?? 64}
        $one_byte_mov_D_stack = {C6 44 24 ?? 44}
        $one_byte_mov_r_stack = {C6 44 24 ?? 72}
        $one_byte_mov_i_stack = {C6 44 24 ?? 69}
        $one_byte_mov_v_stack = {C6 44 24 ?? 76}
        $one_byte_mov_P_stack = {C6 44 24 ?? 50}
        $one_byte_mov_l_stack = {C6 44 24 ?? 6c}
        $one_byte_mov_g_stack = {C6 44 24 ?? 67}
        
        $two_byte_mov_Se_stack = {66 C7 44 24 ?? 53 65}
        $two_byte_mov_eL_stack = {66 C7 44 24 ?? 65 4c}
        $two_byte_mov_Lo_stack = {66 C7 44 24 ?? 4c 6f}
        $two_byte_mov_oa_stack = {66 C7 44 24 ?? 6f 61}
        $two_byte_mov_ad_stack = {66 C7 44 24 ?? 61 64}
        $two_byte_mov_dD_stack = {66 C7 44 24 ?? 64 44}
        $two_byte_mov_Dr_stack = {66 C7 44 24 ?? 44 72}
        $two_byte_mov_ri_stack = {66 C7 44 24 ?? 72 69}
        $two_byte_mov_iv_stack = {66 C7 44 24 ?? 69 76}
        $two_byte_mov_ve_stack = {66 C7 44 24 ?? 76 65}
        $two_byte_mov_er_stack = {66 C7 44 24 ?? 65 72}
        $two_byte_mov_rP_stack = {66 C7 44 24 ?? 72 50}
        $two_byte_mov_Pr_stack = {66 C7 44 24 ?? 50 72}
        $two_byte_mov_vi_stack = {66 C7 44 24 ?? 76 69}
        $two_byte_mov_il_stack = {66 C7 44 24 ?? 69 6c}
        $two_byte_mov_le_stack = {66 C7 44 24 ?? 6c 65}
        $two_byte_mov_eg_stack = {66 C7 44 24 ?? 65 67}
        $two_byte_mov_ge_stack = {66 C7 44 24 ?? 67 65}
        
        $four_byte_mov_SeLo_stack = {C7 44 24 ?? 53 65 4c 6f}
        $four_byte_mov_eLoa_stack = {C7 44 24 ?? 65 4c 6f 61}
        $four_byte_mov_Load_stack = {C7 44 24 ?? 4c 6f 61 64}
        $four_byte_mov_oadD_stack = {C7 44 24 ?? 6f 61 64 44}
        $four_byte_mov_adDr_stack = {C7 44 24 ?? 61 64 44 72}
        $four_byte_mov_dDri_stack = {C7 44 24 ?? 64 44 72 69}
        $four_byte_mov_Driv_stack = {C7 44 24 ?? 44 72 69 76}
        $four_byte_mov_rive_stack = {C7 44 24 ?? 72 69 76 65}
        $four_byte_mov_iver_stack = {C7 44 24 ?? 69 76 65 72}
        $four_byte_mov_verP_stack = {C7 44 24 ?? 76 65 72 50}
        $four_byte_mov_erPr_stack = {C7 44 24 ?? 65 72 50 72}
        $four_byte_mov_rPri_stack = {C7 44 24 ?? 72 50 72 69}
        $four_byte_mov_Priv_stack = {C7 44 24 ?? 50 72 69 76}
        $four_byte_mov_rivi_stack = {C7 44 24 ?? 72 69 76 69}
        $four_byte_mov_ivil_stack = {C7 44 24 ?? 69 76 69 6c}
        $four_byte_mov_vile_stack = {C7 44 24 ?? 76 69 6c 65}
        $four_byte_mov_ileg_stack = {C7 44 24 ?? 69 6c 65 67}
        $four_byte_mov_lege_stack = {C7 44 24 ?? 6c 65 67 65}
        
    condition:
        any of ($one_byte_*) and
        any of ($two_byte_*) and 
        any of ($four_byte_*)
}
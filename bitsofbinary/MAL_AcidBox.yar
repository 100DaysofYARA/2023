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
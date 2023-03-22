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
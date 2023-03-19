/*
Collection of rules to cover the AcidBox malware framework as described in the following blog:
https://unit42.paloaltonetworks.com/acidbox-rare-malware/
*/

rule AcidBox_SSP_DLL_Loader_Format_Strings {
    meta:
        description = "Detects AcidBox SSP DLL loaders, based on a combination of format strings"
        author = "BitsOfBinary"
        reference = "https://unit42.paloaltonetworks.com/acidbox-rare-malware/"
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
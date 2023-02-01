rule SUSP_Macho_ConventionEngine_Base64
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-31"
        version = "1.0"
        description = "using ConventionEngine Style Rules Checking for Macho Files that share some potential functionality via the string "

    strings:
        $ = "base64" nocase ascii wide
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
        1 of them
}

rule SUSP_Macho_ConventionEngine_Hook {
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-31"
        version = "1.0"
        description = "using ConventionEngine Style Rules Checking for Macho Files that share some potential functionality via the string Hook"
    strings:
        $ = "Hook" nocase ascii wide
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE)
        and all of them
}

rule SUSP_Macho_ConventionEngine_Shellcode {
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-31"
        version = "1.0"
        description = "using ConventionEngine Style Rules Checking for Macho Files that share some potential functionality via the string Shellcode"
    strings:
        $ = "Shellcode" nocase ascii wide
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE)
        and all of them
}

rule SUSP_Macho_ConventionEngine_Rootkit {
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-31"
        version = "1.0"
        description = "using ConventionEngine Style Rules Checking for Macho Files that share some potential functionality via the string Rootkit"
    strings:
        $ = "Rootkit" nocase ascii wide
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE)
        and all of them
}

rule SUSP_Macho_ConventionEngine_Trojan {
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-31"
        version = "1.0"
        description = "using ConventionEngine Style Rules Checking for Macho Files that share some potential functionality via the string Trojan"
    strings:
        $ = "Trojan" nocase ascii wide
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE)
        and all of them
}

rule SUSP_Macho_ConventionEngine_Dropper {
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-31"
        version = "1.0"
        description = "using ConventionEngine Style Rules Checking for Macho Files that share some potential functionality via the string Dropper"
    strings:
        $ = "Dropper" nocase ascii wide
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE)
        and all of them
}

rule SUSP_Macho_ConventionEngine_Backdoor {
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-31"
        version = "1.0"
        description = "using ConventionEngine Style Rules Checking for Macho Files that share some potential functionality via the string Backdoor"
    strings:
        $ = "Backdoor" nocase ascii wide
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE)
        and all of them
}

rule SUSP_Macho_ConventionEngine_Spreader {
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-31"
        version = "1.0"
        description = "using ConventionEngine Style Rules Checking for Macho Files that share some potential functionality via the string Spreader"
    strings:
        $ = "Spreader" nocase ascii wide
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE)
        and all of them
}

rule SUSP_Macho_ConventionEngine_Loader {
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-31"
        version = "1.0"
        description = "using ConventionEngine Style Rules Checking for Macho Files that share some potential functionality via the string Loader"
    strings:
        $ = "Loader" nocase ascii wide
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE)
        and all of them
}


rule SUSP_Macho_ConventionEngine_Inject {
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-31"
        version = "1.0"
        description = "using ConventionEngine Style Rules Checking for Macho Files that share some potential functionality via the string Inject"
    strings:
        $ = "Inject" nocase ascii wide
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE)
        and all of them
}


rule SUSP_Macho_ConventionEngine_Reflect {
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-31"
        version = "1.0"
        description = "using ConventionEngine Style Rules Checking for Macho Files that share some potential functionality via the string Reflect"
    strings:
        $ = "Reflect" nocase ascii wide
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE)
        and all of them
}

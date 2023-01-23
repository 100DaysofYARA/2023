rule SUSP_MacOS_CommandRef_networksetup
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-23"
        version = "1.0"
        description = "check for references to networksetup utility"

    strings:
        $ = "networksetup" ascii wide
    condition:
        all of them
}


rule SUSP_MacOS_CommandRef_networksetup_b64
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-23"
        version = "1.0"
        description = "check for references to networksetup utility"

    strings:
        $ = "networksetup" base64 base64wide
    condition:
        all of them
}

rule SUSP_MacOS_CommandRef_networksetup_xor
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-23"
        version = "1.0"
        description = "check for references to networksetup utility"

    strings:
        $ = "networksetup" xor(0x01-0xff) ascii wide
    condition:
        all of them
}

rule SUSP_MacOS_CommandRef_networksetup_mutation
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-23"
        version = "1.0"
        description = "check for references to networksetup utility"

    strings:
        $networksetup_flipflop = "enwtrosktepu" nocase ascii wide
        $networksetup_reverse = "puteskrowten" nocase ascii wide
        $networksetup_hex_enc_str = "6e6574776f726b7365747570" nocase ascii wide
        $networksetup_decimal = "110 101 116 119 111 114 107 115 101 116 117 112" nocase ascii wide
        $networksetup_fallchill = "mvgdliphvgfk" nocase ascii wide
        $networksetup_stackpush = "hetuphorkshnetw" nocase ascii wide
        $networksetup_stackpushnull = "hetup\x00horkshnetw" ascii wide
        $networksetup_stackpushdoublenull = "hetup\x00\x00horkshnetw" ascii wide
    condition:
        all of them
}

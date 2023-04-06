rule Compromised_DLL_3CX
{
    meta:
        author = "Daniel Mayer (daniel@stairwell.com)"
        description = "A rule for detecting a malicious DLL included in legitimate 3CX installers"
        version = "1.0"
        date = "2023-03-29"
        reference1="https://twitter.com/DanielStepanic/status/1641115302246207489"
        reference2="https://twitter.com/DanielStepanic/status/1641115302246207489"
        sample1="aa4e398b3bd8645016d8090ffc77d15f926a8e69258642191deb4e68688ff973"
    strings:
        $s_tutma = "__tutma"
        $s_tutmc = "__tutmc"
        $s_manifest = "manifest" wide
        $s_crypto = "Software\\Microsoft\\Cryptography" wide
        $s_guid = "MachineGuid"
        $s_github = "raw.githubusercontent.com" wide
        $url = "https://raw.githubusercontent.com/IconStorages/images" wide
        $lcg_chunk_1 = { 
            41 81 C0 87 D6 12 00                    // add     r8d, 12D687h
            02 C8                                   // add     cl, al
            49 C1 E9 20                             // shr     r9, 20h
            41 88 4B 03                             // mov     [r11+3], cl
            4D 03 D1                                // add     r10, r9
            8B C8                                   // mov     ecx, eax
            45 8B CA                                // mov     r9d, r10d
            C1 E1 05                                // shl     ecx, 5
            33 C1                                   // xor     eax, ecx
            41 69 D0 7D 50 BF 12                    // imul    edx, r8d, 12BF507Dh
            8B C8                                   // mov     ecx, eax
            C1 E9 07                                // shr     ecx, 7
            33 C1                                   // xor     eax, ecx
            8B C8                                   // mov     ecx, eax
            C1 E1 16                                // shl     ecx, 16h
         }

    condition:
        filesize < 500KB and ( all of ($s*) or ( 3 of ( $s* ) and $lcg_chunk_1 ) or $url )
}
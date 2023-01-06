rule Stairwell_CobaltStrike_Stager_API_Hashing
{
    meta:
        author = "Daniel Mayer (daniel@stairwell.com)"
        description = "Example rule using multiline bytes and comments to annotate instructions. Detects the ror13 API hashing (ror13 is also used by metasploit) routine used by Cobalt Strike"
        hash_x64 = "61b4c29f349f4c5d377934490ca117f87c96b2817e74cea4b2019bea09a9f7fc"
        hash_x86 = "a6f71c9f0ebe8a236e60c6219ca8466c8a2dfbeedfe3fa26bf89b6fb745ee71d"
        version = "1.0"
        date = "2023-01-05"

    strings:
        $x64 = {
            // loc_2D:
            48 31 C0        // xor     rax, rax
            AC              // lodsb
            3C 61           // cmp     al, 61h  ; 'a'
            7C 02           // jl      short loc_37
            2C 20           // sub     al, 20h  ; ' '
            // loc_37
            41 C1 C9 0D     // ror     r9d, 0Dh ; 13
            41 01 C1        // add     r9d, eax
            E2 ED           // loop    loc_2D
         }

         $x86 = {
            // loc_1E:
            31 C0           // xor     eax, eax
            AC              // lodsb
            3C 61           // cmp     al, 61h  ; 'a'
            7C 02           // jl      short loc_27
            2C 20           // sub     al, 20h  ; ' '
            // loc_27:
            C1 CF 0D        // ror     edi, 0Dh ; 13
            01 C7           // add     edi, eax
            E2 F0           // loop    loc_1E
         }

    condition:
        any of them
}

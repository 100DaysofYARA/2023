rule Stairwell_3CX_Compromise_Final_Payload_Gopuram_Loader
{
    meta:
        author = "Daniel Mayer (daniel@stairwell.com)"
        description = "A rule for detecting the Gopuram loader found on disk at selectively targeted organizations post-3CX supply-chain compromise"
        version = "1.0"
        date = "2023-04-03"
        reference1="https://twitter.com/kucher1n/status/1642886340105601029"
        reference2="https://securelist.com/gopuram-backdoor-deployed-through-3cx-supply-chain-attack/109344/"
        sample1="97b95b4a5461f950e712b82783930cb2a152ec0288c00a977983ca7788342df7"
    
    strings:
        $filepath = "%s\\config\\TxR\\%s.TxR.0.regtrans-ms"
        $module_name_hashing_round = { 
            D1 E8                                         // shr     eax, 1
            33 C3                                         // xor     eax, ebx
            D1 EB                                         // shr     ebx, 1
            A8 01                                         // test    al, 1
            ?? ??                                         // jz      short loc_??
            81 F3 25 A3 87 DE                             // xor     ebx, 0DE87A325h
         }
        $module_name_hashing_check = {
            3D B8 7D CB 38                                // cmp     eax, 38CB7DB8h
        }
    condition:
        $filepath or all of ($module_name_hashing*)
}

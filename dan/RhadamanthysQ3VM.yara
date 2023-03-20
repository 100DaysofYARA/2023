rule RhadamanthysQ3VM
{
    meta:
        author = "Daniel Mayer (daniel@stairwell.com)"
        description = "Detects q3vm embedded in executables - used by Rhadamanthys"
        version = "1.0"
        date = "2023-03-03"
        source1 = "https://www.zscaler.com/blogs/security-research/technical-analysis-rhadamanthys-obfuscation-techniques"
        source2 = "https://raw.githubusercontent.com/jnz/q3vm/master/src/vm/vm.c"
    strings:
        $BEEF = { 
            C7 45 00 EF BE 00 00                          // mov     dword ptr [ebp+0], 0BEEFh
        }
        $DISPATCH = {
            0F B6 CB                                      // movzx   ecx, bl
            8D 53 FF                                      // lea     edx, [ebx-1]
            0F B6 C2                                      // movzx   eax, dl
            8B 44 85 00                                   // mov     eax, [ebp+eax*4+0]
            8D 74 8D 00                                   //lea     esi, [ebp+ecx*4+0]
        }
        $OP_NEGI = {
            0F B6 D3                                      // movzx   edx, bl
            F7 D9                                         // neg     ecx
            89 4C 95 00                                   // mov     [ebp+edx*4+0], ecx
        }
        $OP_ADD = {
            FE CB                                         // dec     bl
            03 C1                                         // add     eax, ecx
            0F B6 CB                                      // movzx   ecx, bl
            89 44 8D 00                                   // mov     [ebp+ecx*4+0], eax
        }
        $OP_MODI = {
            99                                            // cdq
            FE CB                                         // dec     bl
            F7 F9                                         // idiv    ecx
            0F B6 C3                                      // movzx   eax, bl
            89 54 85 00                                   // mov     [ebp+eax*4+0], edx
        }
        $OP_BXOR = {
            FE CB                                         // dec     bl
            0F B6 D3                                      // movzx   edx, bl
            33 C1                                         // xor     eax, ecx
            89 44 95 00                                   // mov     [ebp+edx*4+0], eax
        }

    condition:
        ( $BEEF or $DISPATCH ) and 3 of ($OP*)
}
rule dev_3CX_Gopuram_AppleJeus_Shellcode_Hunt
{
    meta:
        author = "Daniel Mayer (daniel@stairwell.com)"
        description = "A rule for Gopuram shellcode based off of a screenshot of ida in Kaspersky's blog. No promises."
        version = "1.0"
        date = "2023-04-03"
        reference1="https://securelist.com/gopuram-backdoor-deployed-through-3cx-supply-chain-attack/109344/"
    strings:
        $test_hunt = { 
            59                   // pop rcx
            49 89 C8             // mov r8, rcx
            48 81 C1 58 06 00 00 // add rcx, 0x658
            BA DA F4 58 F5       // mov edx, 0xf558f4da
            49 81 C0 58 D0 06 00 // add r8,0x6d058
            41 B9 39 00 00 00    // mov r9d, 0x39
            }

    condition:
        all of them
}
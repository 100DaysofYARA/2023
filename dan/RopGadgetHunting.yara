rule RopGadgetHunting
{
    meta:
        author = "Daniel Mayer (daniel@stairwell.com)"
        description = "An experimental rule for detecting ROP gadget hunting"
        version = "1.0"
        date = "2023-02-24"
        reference1="https://github.com/LloydLabs/ntqueueapcthreadex-ntdll-gadget-injection"

    strings:
        // matches on IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE flag comparison
        $flag_hunt = {      
            25 20 00 00 20  // and     eax, 20000020h
            3D 20 00 00 20  // cmp     eax, 20000020h
            }

        // matches on comparison between a given byte and the ret opcode
        $ret_cmp = { 
            80 [1-2] C3     //cmp [eax + ?], 0C3h
            } 


    condition:
        uint16(0) == 0x5A4D and all of them
}


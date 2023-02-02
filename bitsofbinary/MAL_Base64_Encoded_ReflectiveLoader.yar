rule Reflective_Loader_Shellcode_Base64_Encoded {
    meta:
        author = "BitsOfBinary"
        description = "Detects Base64 encoded reflective loader shellcode stub, seen for example in Meterpreter samples"
        reference = "https://bitsofbinary.github.io/yara/2023/02/02/100daysofyara-day-33.html"
        version = "1.0"
        date = "2023-02-02"
        DaysofYARA = "33/100"
        hash = "ed48d56a47982c3c9b39ee8859e0b764454ab9ac6e7a7866cdef5c310521be19"
        hash = "76d54a57bf9521f6558b588acd0326249248f91b27ebc25fd94ebe92dc497809"
        hash = "1db32411a88725b259a7f079bdebd5602f11130f71ec35bec9d18134adbd4352"
    
    strings:
        // pop     r10
        // push    r10
        // push    rbp
        // mov     rbp, rsp
        // sub     rsp, 20h
        // and     rsp, 0FFFFFFFFFFFFFFF0h
        // call    $+5
        // pop     rbx
        $ = "\x4D\x5A\x41\x52\x55\x48\x89\xE5\x48\x83\xEC\x20\x48\x83\xE4\xF0\xE8\x00\x00\x00\x00\x5B" base64 base64wide
       
    condition:
        any of them
}
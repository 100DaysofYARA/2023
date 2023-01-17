rule INFO_Macho_LowLevel_API_task_info
{
    meta:
        description = "check Macho files for low level API of task_info, used by _xpn_ to get dydl in memory base address"
        author = "Greg Lesnewich"
        date = "2023-01-17"
        version = "1.0"
        reference = "https://blog.xpnsec.com/restoring-dyld-memory-loading/"
    strings:
        $ = "task_info" nocase ascii wide
    condition:
        (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
        all of them
}

rule INFO_Macho_LowLevel_Dydl_API_mmap
{
    meta:
        description = "check Macho files for low level API of mmap to map a file into memory"
        author = "Greg Lesnewich"
        date = "2023-01-17"
        version = "1.0"
        reference = "https://blog.xpnsec.com/restoring-dyld-memory-loading/"
    strings:
        $ = "mmap" ascii wide
    condition:
        (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
        all of them
}

rule INFO_Macho_LowLevel_Dydl_API_pread
{
    meta:
        description = "check Macho files for low level API of pread to read from a given input"
        author = "Greg Lesnewich"
        date = "2023-01-17"
        version = "1.0"
        reference = "https://blog.xpnsec.com/restoring-dyld-memory-loading/"
    strings:
        $ = "pread" ascii wide
    condition:
        (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
        all of them
}

rule INFO_Macho_LowLevel_Dydl_API_fcntl
{
    meta:
        description = "check Macho files for low level API of fcntl which is used to control open files and provides for control over descriptors"
        author = "Greg Lesnewich"
        date = "2023-01-17"
        version = "1.0"
        reference = "https://blog.xpnsec.com/restoring-dyld-memory-loading/"
    strings:
        $ = "fcntl" ascii wide
    condition:
        (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
        all of them
}

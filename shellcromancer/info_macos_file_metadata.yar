rule info_macos_file_metadata
{
  meta:
    description = "Identify macho executable with references to file metadata."
    author = "@shellcromancer"
    version = "1.0"
    date = "2023.04.08"
    DaysofYARA = "98/100"

  strings:
    $cmd0 = "mdls"
    $cmd1 = { 6C 73 [0-6] 20 [0-6] 2D [0-8] 6C [0-8] 40 }

  condition:
    (
    uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
    uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
    uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
    uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
    uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
    uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and
    uint32(0xc) == 0x2 and  // mach_header->filetype == MH_EXECUTE
    any of them
}

rule info_python_nuitka
{
  meta:
    description = "Identify Nuitka-compiled Python executable"
    author = "@shellcromancer"
    version = "1.0"
    date = "2023.03.28"
    reference = "https://nuitka.net"
    DaysofYARA = "87/100"

  strings:
    $nuitka = "nuitka" nocase

  condition:
    (
    int16(0) == 0x5a4d or  // PE
    uint32(0) == 0x464c457f or  // ELF
    uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
    uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
    uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
    uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
    uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
    uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and #nuitka > 10
}

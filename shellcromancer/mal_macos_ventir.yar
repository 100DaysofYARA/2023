rule mal_macos_ventir
{
  meta:
    description = "Identify macOS Ventir backdoor."
    author = "@shellcromancer"
    version = "1.0"
    date = "2023.03.19"
    references = "https://securelist.com/the-ventir-trojan-assemble-your-macos-spy/67267/"
    sample = "59539ff9af82c0e4e73809a954cf2776636774e6c42c281f3b0e5f1656e93679"
    DaysofYARA = "79/100"

  strings:
    $s0 = "/proc/self/exe"
    $s1 = "/bin/mv -f %s/updated.kext /System/Library/Extensions/updated.kext"

  condition:
    (
    uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
    uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
    uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
    uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
    uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
    uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and
    all of them
}

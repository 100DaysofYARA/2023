rule info_macos_scpt_applet
{
  meta:
    description = "Identify macOS AppleScript Applet stubs."
    author = "@shellcromancer"
    version = "1.0"
    date = "2023.04.06"
    DaysofYARA = "96/100"

  strings:
    $s0 = "_OpenDefaultComponent"
    $s1 = "_CallComponentDispatch"

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

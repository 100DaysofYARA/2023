rule mal_macos_dacls
{
  meta:
    description = "Identify the macOS DACLs backdoor."
    author = "@shellcromancer"
    version = "1.0"
    date = "2023.04.07"
    sample = "846d8647d27a0d729df40b13a644f3bffdc95f6d0e600f2195c85628d59f1dc6"
    DaysofYARA = "97/100"

  strings:
    $s0 = "SCAN\t%s\t%d.%d.%d.%d\t%d\n"
    $s1 = "%Y-%m-%d %X"
    $s2 = "{\"result\":\"ok\"}"

    $f0 = "http_send_post"
    $f1 = "fetch_response"
    $f2 = "start_worm_scan"
    $f3 = "MakePacketHeader"

    $n0 = "mata_wc"
    $n1 = "Mata"

  condition:
    (
    uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
    uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
    uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
    uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
    uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
    uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and
    (all of ($s*) or all of ($f*) or all of ($n*))
}

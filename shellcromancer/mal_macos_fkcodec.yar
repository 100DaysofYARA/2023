rule mal_macos_fkcodec {
  meta:
    description = "Identify macOS FKCodec backdoor."
    author = "@shellcromancer"
    version = "1.0"
    date = "2023.03.25"
    reference = "http://www.thesafemac.com/osxfkcodec-a-in-action/"
    sample = "979c6de81cc0f4e0a770f720ab82e8c727a2d422fe6179684b239fe0dc28d86c"
    DaysofYARA = "84/100"

  strings:
    $s0 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:29.0) Gecko/20100101 Firefox/29.0"
    $s1 = "/Users/yuriyfomenko/Develop/vova/projects/vidinstaller"
    $s2 = "safari_name=([^&?]*)"
    $s3 = "/tmp/download/ch.txt"
    $s4 = "/wait"
    $s5 = "/task"

  condition:
    (
    uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
    uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
    uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
    uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
    uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
    uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and
    3 of them
}

rule mal_macos_smoothoperator {
  meta:
    description = "Identify macOS SmoothOperator first stage."
    author = "@shellcromancer"
    version = "1.0"
    date = "2023.03.30"
    references = "https://objective-see.org/blog/blog_0x73.html"
    sample = "a64fa9f1c76457ecc58402142a8728ce34ccba378c17318b3340083eeb7acc67"
    DaysofYARA = "89/100"

  strings:
    $s0 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.128 Safari/53" xor(0x01-0xff)
    $s1 = "3cx_auth_id=%s;3cx_auth_token_content=%s;__tutma" xor(0x01-0xff)
    $s2 = "%s/Library/Application Support/3CX Desktop App/%" xor(0x01-0xff)
    $s3 = "/System/Library/CoreServices/SystemVersion.plist" xor(0x01-0xff)

  condition:
    (
    uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
    uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
    uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
    uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
    uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
    uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and
    2 of them
}

rule mal_macos_smoothoperator_updateagent {
  meta:
    description = "Identify macOS SmoothOperator second stage."
    author = "@shellcromancer"
    version = "1.0"
    date = "2023.04.03"
    references = "https://objective-see.org/blog/blog_0x74.html"
    sample = "6c121f2b2efa6592c2c22b29218157ec9e63f385e7a1d7425857d603ddef8c59"
    DaysofYARA = "93/100"

  strings:
    $s0 = "https://sbmsa.wiki/blog/_insert"
    $s1 = "3cx_auth_id=%s;3cx_auth_token_content=%s;__tutma=true" xor
    $s2 = "%s/Library/Application Support/3CX Desktop App/config.json" xor
    $s3 = "%s/Library/Application Support/3CX Desktop App/.main_storage" xor
    $s4 = "gzip, deflate" xor(0x01-0xff)
    $s5 = "User-Agent" xor(0x01-0xff)
    $s6 = "Connection" xor(0x01-0xff)

    $f0 = "parse_json_config"
    $f1 = "enc_text"

  condition:
    (
    uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
    uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
    uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
    uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
    uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
    uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and
    2 of ($s*) or
    all of ($f*)
}

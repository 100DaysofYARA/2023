rule mal_macos_silver_sparrow_distribution {
  meta:
    description = "Identify macOS SilverSparrow pkg distrubtion scripts."
    author = "@shellcromancer"
    version = "1.0"
    date = "2023.03.23"
    references = "https://redcanary.com/blog/clipping-silver-sparrows-wings/"
    sample = "b60f1c6b95b8de397e7d92072412d1970ba474ff168ccabbc641d2a65b307b8a"
    DaysofYARA = "82/100"

  strings:
    $a0 = { 61 70 70 65 6E 64 4C 69 6E 65 (78 | 79) }
    $a1 = { 77 72 69 74 65 54 6F 46 69 6C 65 (78 | 79) }

    $b0 = "/usr/libexec/PlistBuddy -c 'Add :ProgramArguments:2 string \\\"~/Library/Application"
    $b1 = "${initAgentPath};"

  condition:
    any of ($a*) and all of ($b*)
}

rule mal_macos_silver_sparrow {
  meta:
    description = "Identify macOS SilverSparrow distrubtion scripts."
    author = "@shellcromancer"
    version = "1.0"
    date = "2023.03.24"
    references = "https://redcanary.com/blog/clipping-silver-sparrows-wings/"
    sample = "b60f1c6b95b8de397e7d92072412d1970ba474ff168ccabbc641d2a65b307b8a"
    DaysofYARA = "83/100"

  strings:
    $a0 = {
    48 bf 48 65 6c 6c 6f 2c 20 57  // mov     rdi, 'Hello, W'
    48 be 6f 72 6c 64 21 00 00 ed  // mov     rsi, 'orld!\x00\x00\xed'
    e8                             // call    _$s7SwiftUI18LocalizedStringKeyV13stringLiteralACSS_tcfC
    }
    $a1 = {
    48 bf 59 6f 75 20 64 69 64 20  // mov     rdi, 'You did '
    48 be 69 74 21 00 00 00 00 eb  // mov     rsi, 'it!\x00\x00\x00\x00\xeb'
    e8                             // call    _$s7SwiftUI18LocalizedStringKeyV13stringLiteralACSS_tcfC
    }

    $b0 = "SwiftUI6VStackVMn"

  condition:
    (
    uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
    uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
    uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
    uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
    uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
    uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and
    any of ($a*) and all of ($b*)
}

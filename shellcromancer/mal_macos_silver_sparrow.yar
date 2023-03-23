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

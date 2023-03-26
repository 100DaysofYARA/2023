rule mal_macos_macstealer {
  meta:
    description = "Identify macOS MacStealer malware."
    author = "@shellcromancer"
    version = "1.0"
    date = "2023.03.26"
    references = "https://www.uptycs.com/blog/macstealer-command-and-control-c2-malware"
    sample = "1153fca0b395b3f219a6ec7ecfc33f522e7b8fc6676ecb1e40d1827f43ad22be"
    DaysofYARA = "85/100"

  strings:
    // config imports
    $s0 = "data.keychain"
    $s1 = "data.exdocusdecrypt"

    // support_file_extensions
    $s2 = { 74 78 74 [1-3] 75 2e 64 6f 63 [1-3] 75 2e 64 6f 63 78 [1-3] 75 2e 70 64 66 [1-3] 75 2e 78 6c 73 [1-3] 75 2e 78 6c 73 78 [1-3] 75 2e 70 70 74 [1-3] 75 2e 70 70 74 78 [1-3] 75 2e 6a 70 67 [1-3] 75 2e 70 6e 67 [1-3] 75 2e 62 6d 70 [1-3] 75 2e 6d 70 33 [1-3] 75 2e 7a 69 70 [1-3] 75 2e 72 61 72 [1-3] 75 2e 70 79 [1-3] 61 64 62 [1-3] 75 2e 63 73 76 [1-3] 75 2e 6a 70 65 67 }
    // support_folder_names
    $s3 = { 61 44 65 73 6b 74 6f 70 [1-3] 61 44 6f 63 75 6d 65 6e 74 73 [1-3] 61 44 6f 77 6e 6c 6f 61 64 73 [1-3] 61 4d 6f 76 69 65 73 [1-3] 61 4d 75 73 69 63 [1-3] 61 50 69 63 74 75 72 65 73 [1-3] 61 50 75 62 6c 69 63 }

    // bot id
    $s4 = "B8729059DDBF6359F136F699030BD4F5"

    // OSAScript
    $s5 = "osascript -e \\'display dialog \\\"{message}\\\" with title \\\"{title}\\\" with icon caution default answer \\\"\\\" with hidden answer"

    // keychain 
    $s6 = "security list-keychains"

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

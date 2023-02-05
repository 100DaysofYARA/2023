rule SUSP_Macho_Bin_Ref_bash {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like bash"
    strings:
        $ = "bin/bash" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_brew {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like brew"
    strings:
        $ = "bin/brew" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_chmH {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like chmH"
    strings:
        $ = "bin/chmH" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_chmod {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like chmod"
    strings:
        $ = "bin/chmod" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_chown {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like chown"
    strings:
        $ = "bin/chown" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_codesign {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like codesign"
    strings:
        $ = "bin/codesign" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_com {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like com"
    strings:
        $ = "bin/com" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_curl {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like curl"
    strings:
        $ = "bin/curl" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_defaults {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like defaults"
    strings:
        $ = "bin/defaults" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_diskutil {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like diskutil"
    strings:
        $ = "bin/diskutil" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_ditto {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like ditto"
    strings:
        $ = "bin/ditto" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_echo {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like echo"
    strings:
        $ = "bin/echo" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_find {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like find"
    strings:
        $ = "bin/find" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_hdiutil {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like hdiutil"
    strings:
        $ = "bin/hdiutil" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_iWorkServices {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like iWorkServices"
    strings:
        $ = "bin/iWorkServices" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_installer {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like installer"
    strings:
        $ = "bin/installer" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_jump {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like jump"
    strings:
        $ = "bin/jump" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_kextload {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like kextload"
    strings:
        $ = "bin/kextload" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_kextunload {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like kextunload"
    strings:
        $ = "bin/kextunload" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_kill {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like kill"
    strings:
        $ = "bin/kill" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_killall {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like killall"
    strings:
        $ = "bin/killall" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_launchctl {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like launchctl"
    strings:
        $ = "bin/launchctl" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_login {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like login"
    strings:
        $ = "bin/login" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_ls {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like ls"
    strings:
        $ = "bin/ls" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_mount {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like mount"
    strings:
        $ = "bin/mount" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_mv {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like mv"
    strings:
        $ = "bin/mv" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_my {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like my"
    strings:
        $ = "bin/my" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_networksetup {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like networksetup"
    strings:
        $ = "bin/networksetup" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_open {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like open"
    strings:
        $ = "bin/open" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_passwd {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like passwd"
    strings:
        $ = "bin/passwd" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_pkexec {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like pkexec"
    strings:
        $ = "bin/pkexec" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_pkgutil {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like pkgutil"
    strings:
        $ = "bin/pkgutil" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_python {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like python"
    strings:
        $ = "bin/python" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_rm {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like rm"
    strings:
        $ = "bin/rm" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_ruby {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like ruby"
    strings:
        $ = "bin/ruby" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_screencapture {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like screencapture"
    strings:
        $ = "bin/screencapture" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_sh {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like sh"
    strings:
        $ = "bin/sh" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_socat {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like socat"
    strings:
        $ = "bin/socat" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_spctl {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like spctl"
    strings:
        $ = "bin/spctl" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_sqlite3 {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like sqlite3"
    strings:
        $ = "bin/sqlite3" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_sysctl {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like sysctl"
    strings:
        $ = "bin/sysctl" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_tar {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like tar"
    strings:
        $ = "bin/tar" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_tor {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like tor"
    strings:
        $ = "bin/tor" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_xauth {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like xauth"
    strings:
        $ = "bin/xauth" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

rule SUSP_Macho_Bin_Ref_zip {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-05"
        version = "1.0"
        description = "check Macho files for the reference to file under /bin/ like zip"
    strings:
        $ = "bin/zip" ascii wide
    condition:
        (
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of them
}

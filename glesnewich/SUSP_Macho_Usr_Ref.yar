rule SUSP_Macho_Usr_Ref_4bdy {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like 4bdy "
    strings:
        $ = "usr/4b/dy" ascii wide
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
rule SUSP_Macho_Usr_Ref_bin {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin "
    strings:
        $ = "usr/bin" ascii wide
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
rule SUSP_Macho_Usr_Ref_bin_inclu {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_inclu "
    strings:
        $ = "usr/bin/../inclu" ascii wide
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
rule SUSP_Macho_Usr_Ref_bin_include_c {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_include_c "
    strings:
        $ = "usr/bin/../include/c" ascii wide
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
rule SUSP_Macho_Usr_Ref_bin_codesign {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_codesign "
    strings:
        $ = "usr/bin/codesign" ascii wide
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
rule SUSP_Macho_Usr_Ref_bin_curl {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_curl "
    strings:
        $ = "usr/bin/curl" ascii wide
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
rule SUSP_Macho_Usr_Ref_bin_defaults {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_defaults "
    strings:
        $ = "usr/bin/defaults" ascii wide
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
rule SUSP_Macho_Usr_Ref_bin_diskutil {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_diskutil "
    strings:
        $ = "usr/bin/diskutil" ascii wide
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
rule SUSP_Macho_Usr_Ref_bin_ditto {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_ditto "
    strings:
        $ = "usr/bin/ditto" ascii wide
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
rule SUSP_Macho_Usr_Ref_bin_find {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_find "
    strings:
        $ = "usr/bin/find" ascii wide
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
rule SUSP_Macho_Usr_Ref_bin_hdiutil {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_hdiutil "
    strings:
        $ = "usr/bin/hdiutil" ascii wide
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
rule SUSP_Macho_Usr_Ref_bin_iWorkServices {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_iWorkServices "
    strings:
        $ = "usr/bin/iWorkServices" ascii wide
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
rule SUSP_Macho_Usr_Ref_bin_killall {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_killall "
    strings:
        $ = "usr/bin/killall" ascii wide
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
rule SUSP_Macho_Usr_Ref_bin_login {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_login "
    strings:
        $ = "usr/bin/login" ascii wide
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
rule SUSP_Macho_Usr_Ref_bin_open {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_open "
    strings:
        $ = "usr/bin/open" ascii wide
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
rule SUSP_Macho_Usr_Ref_bin_passwd {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_passwd "
    strings:
        $ = "usr/bin/passwd" ascii wide
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
rule SUSP_Macho_Usr_Ref_bin_pkexec {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_pkexec "
    strings:
        $ = "usr/bin/pkexec" ascii wide
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
rule SUSP_Macho_Usr_Ref_bin_python {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_python "
    strings:
        $ = "usr/bin/python" ascii wide
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
rule SUSP_Macho_Usr_Ref_bin_ruby {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_ruby "
    strings:
        $ = "usr/bin/ruby" ascii wide
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
rule SUSP_Macho_Usr_Ref_bin_sqlite3 {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_sqlite3 "
    strings:
        $ = "usr/bin/sqlite3" ascii wide
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
rule SUSP_Macho_Usr_Ref_bin_tar {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_tar "
    strings:
        $ = "usr/bin/tar" ascii wide
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
rule SUSP_Macho_Usr_Ref_bin_zip {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like bin_zip "
    strings:
        $ = "usr/bin/zip" ascii wide
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
rule SUSP_Macho_Usr_Ref_db_dyld {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like db_dyld "
    strings:
        $ = "usr/db/dyld" ascii wide
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
rule SUSP_Macho_Usr_Ref_dict_words {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like dict_words "
    strings:
        $ = "usr/dict/words" ascii wide
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
rule SUSP_Macho_Usr_Ref_include_ {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like include_ "
    strings:
        $ = "usr/include/" ascii wide
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
rule SUSP_Macho_Usr_Ref_include_c {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like include_c "
    strings:
        $ = "usr/include/c" ascii wide
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
rule SUSP_Macho_Usr_Ref_include_ctype {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like include_ctype "
    strings:
        $ = "usr/include/ctype" ascii wide
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
rule SUSP_Macho_Usr_Ref_include_dispatch_once {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like include_dispatch_once "
    strings:
        $ = "usr/include/dispatch/once" ascii wide
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
rule SUSP_Macho_Usr_Ref_include_dispatch_queue {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like include_dispatch_queue "
    strings:
        $ = "usr/include/dispatch/queue" ascii wide
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
rule SUSP_Macho_Usr_Ref_include_libkern_i386 {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like include_libkern_i386 "
    strings:
        $ = "usr/include/libkern/i386/" ascii wide
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
rule SUSP_Macho_Usr_Ref_include_math {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like include_math "
    strings:
        $ = "usr/include/math" ascii wide
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
rule SUSP_Macho_Usr_Ref_include_secure {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like include_secure "
    strings:
        $ = "usr/include/secure/" ascii wide
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
rule SUSP_Macho_Usr_Ref_li {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like li "
    strings:
        $ = "usr/li" ascii wide
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
rule SUSP_Macho_Usr_Ref_lib {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib "
    strings:
        $ = "usr/lib" ascii wide
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

rule SUSP_Macho_Usr_Ref_lib_apple_SDKs {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_apple_SDKs "
    strings:
        $ = "usr/lib/apple/SDKs/" ascii wide
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
rule SUSP_Macho_Usr_Ref_lib_arc_libarclite {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_arc_libarclite "
    strings:
        $ = "usr/lib/arc/libarclite" ascii wide
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
rule SUSP_Macho_Usr_Ref_lib_dyld {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_dyld "
    strings:
        $ = "usr/lib/dyld" ascii wide
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
rule SUSP_Macho_Usr_Ref_lib_gcc {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_gcc "
    strings:
        $ = "usr/lib/gcc/i686" ascii wide
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
rule SUSP_Macho_Usr_Ref_lib_libDiagnosticMessagesClient {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_libDiagnosticMessagesClient "
    strings:
        $ = "usr/lib/libDiagnosticMessagesClient." ascii wide
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
rule SUSP_Macho_Usr_Ref_lib_libSystem {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_libSystem "
    strings:
        $ = "usr/lib/libSystem" ascii wide
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
rule SUSP_Macho_Usr_Ref_lib_libc {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_libc "
    strings:
        $ = "usr/lib/libc" ascii wide
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
rule SUSP_Macho_Usr_Ref_lib_libcrypto {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_libcrypto "
    strings:
        $ = "usr/lib/libcrypto" ascii wide
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
rule SUSP_Macho_Usr_Ref_lib_libcurl {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_libcurl "
    strings:
        $ = "usr/lib/libcurl" ascii wide
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
rule SUSP_Macho_Usr_Ref_lib_libgcc {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_libgcc "
    strings:
        $ = "usr/lib/libgcc" ascii wide
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
rule SUSP_Macho_Usr_Ref_lib_libiconv {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_libiconv "
    strings:
        $ = "usr/lib/libiconv" ascii wide
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
rule SUSP_Macho_Usr_Ref_lib_libicucore {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_libicucore "
    strings:
        $ = "usr/lib/libicucore" ascii wide
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
rule SUSP_Macho_Usr_Ref_lib_libobjc {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_libobjc "
    strings:
        $ = "usr/lib/libobjc" ascii wide
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
rule SUSP_Macho_Usr_Ref_lib_libpcap {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_libpcap "
    strings:
        $ = "usr/lib/libpcap" ascii wide
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
rule SUSP_Macho_Usr_Ref_lib_libresolv {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_libresolv "
    strings:
        $ = "usr/lib/libresolv" ascii wide
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
rule SUSP_Macho_Usr_Ref_lib_libsqlite3 {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_libsqlite3 "
    strings:
        $ = "usr/lib/libsqlite3" ascii wide
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
rule SUSP_Macho_Usr_Ref_lib_libstdc {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_libstdc "
    strings:
        $ = "usr/lib/libstdc" ascii wide
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
rule SUSP_Macho_Usr_Ref_lib_libutil {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_libutil "
    strings:
        $ = "usr/lib/libutil" ascii wide
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
rule SUSP_Macho_Usr_Ref_lib_libz {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_libz "
    strings:
        $ = "usr/lib/libz" ascii wide
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
rule SUSP_Macho_Usr_Ref_lib_locale_TZ_GC {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like lib_locale_TZ_GC "
    strings:
        $ = "usr/lib/locale/TZ/GC" ascii wide
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
rule SUSP_Macho_Usr_Ref_libH {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like libH "
    strings:
        $ = "usr/libH" ascii wide
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
rule SUSP_Macho_Usr_Ref_libexec_PlistBuddy {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like libexec_PlistBuddy "
    strings:
        $ = "usr/libexec/PlistBuddy" ascii wide
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
rule SUSP_Macho_Usr_Ref_llvm {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like llvm "
    strings:
        $ = "usr/llvm" ascii wide
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
rule SUSP_Macho_Usr_Ref_local {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local "
    strings:
        $ = "usr/local" ascii wide
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
rule SUSP_Macho_Usr_Ref_local_McAfee {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_McAfee "
    strings:
        $ = "usr/local/McAfee" ascii wide
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
rule SUSP_Macho_Usr_Ref_local_bin {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_bin "
    strings:
        $ = "usr/local/bin" ascii wide
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
rule SUSP_Macho_Usr_Ref_local_bin_brew {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_bin_brew "
    strings:
        $ = "usr/local/bin/brew" ascii wide
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
rule SUSP_Macho_Usr_Ref_local_bin_com_adobe_acc_installer {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_bin_com_adobe_acc_installer "
    strings:
        $ = "usr/local/bin/com.adobe.acc.installer" ascii wide
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
rule SUSP_Macho_Usr_Ref_local_bin_com_adobe_acc_localhost {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_bin_com_adobe_acc_localhost "
    strings:
        $ = "usr/local/bin/com.adobe.acc.localhost" ascii wide
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
rule SUSP_Macho_Usr_Ref_local_bin_com_adobe_acc_network {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_bin_com_adobe_acc_network "
    strings:
        $ = "usr/local/bin/com.adobe.acc.network" ascii wide
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
rule SUSP_Macho_Usr_Ref_local_bin_socat {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_bin_socat "
    strings:
        $ = "usr/local/bin/socat" ascii wide
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
rule SUSP_Macho_Usr_Ref_local_bin_tor {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_bin_tor "
    strings:
        $ = "usr/local/bin/tor" ascii wide
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
rule SUSP_Macho_Usr_Ref_local_go {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_go "
    strings:
        $ = "usr/local/go" ascii wide
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
rule SUSP_Macho_Usr_Ref_local_lib {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_lib "
    strings:
        $ = "usr/local/lib" ascii wide
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
rule SUSP_Macho_Usr_Ref_local_lib_AdobePIM {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_lib_AdobePIM "
    strings:
        $ = "usr/local/lib/AdobePIM" ascii wide
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
rule SUSP_Macho_Usr_Ref_local_lib_ladspa {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_lib_ladspa "
    strings:
        $ = "usr/local/lib/ladspa" ascii wide
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
rule SUSP_Macho_Usr_Ref_local_lib_libvorbis {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_lib_libvorbis "
    strings:
        $ = "usr/local/lib/libvorbis" ascii wide
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
rule SUSP_Macho_Usr_Ref_local_lib_libvorbisenc {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_lib_libvorbisenc "
    strings:
        $ = "usr/local/lib/libvorbisenc" ascii wide
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
rule SUSP_Macho_Usr_Ref_local_lib_libvorbisfile {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_lib_libvorbisfile "
    strings:
        $ = "usr/local/lib/libvorbisfile" ascii wide
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
rule SUSP_Macho_Usr_Ref_local_lib_sox {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_lib_sox "
    strings:
        $ = "usr/local/lib/sox" ascii wide
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
rule SUSP_Macho_Usr_Ref_local_sbin {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_sbin "
    strings:
        $ = "usr/local/sbin" ascii wide
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
rule SUSP_Macho_Usr_Ref_local_ssl {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_ssl "
    strings:
        $ = "usr/local/ssl" ascii wide
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
rule SUSP_Macho_Usr_Ref_local_ssl_cert_pem {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_ssl_cert_pem "
    strings:
        $ = "usr/local/ssl/cert.pem" ascii wide
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
rule SUSP_Macho_Usr_Ref_local_ssl_certs {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_ssl_certs "
    strings:
        $ = "usr/local/ssl/certs" ascii wide
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
rule SUSP_Macho_Usr_Ref_local_ssl_lib_engines {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_ssl_lib_engines "
    strings:
        $ = "usr/local/ssl/lib/engines" ascii wide
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
rule SUSP_Macho_Usr_Ref_local_ssl_private {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like local_ssl_private "
    strings:
        $ = "usr/local/ssl/private" ascii wide
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
rule SUSP_Macho_Usr_Ref_sbin {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like sbin "
    strings:
        $ = "usr/sbin" ascii wide
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
rule SUSP_Macho_Usr_Ref_sbin_chown {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like sbin_chown "
    strings:
        $ = "usr/sbin/chown" ascii wide
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
rule SUSP_Macho_Usr_Ref_sbin_installer {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like sbin_installer "
    strings:
        $ = "usr/sbin/installer" ascii wide
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
rule SUSP_Macho_Usr_Ref_sbin_networksetup {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like sbin_networksetup "
    strings:
        $ = "usr/sbin/networksetup" ascii wide
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
rule SUSP_Macho_Usr_Ref_sbin_pkgutil {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like sbin_pkgutil "
    strings:
        $ = "usr/sbin/pkgutil" ascii wide
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
rule SUSP_Macho_Usr_Ref_sbin_screencapture {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like sbin_screencapture "
    strings:
        $ = "usr/sbin/screencapture" ascii wide
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
rule SUSP_Macho_Usr_Ref_sbin_spctl {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like sbin_spctl "
    strings:
        $ = "usr/sbin/spctl" ascii wide
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
rule SUSP_Macho_Usr_Ref_share_lib_zoneinfo {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like share_lib_zoneinfo "
    strings:
        $ = "usr/share/lib/zoneinfo/" ascii wide
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
rule SUSP_Macho_Usr_Ref_share_lib_zoneinfo_bad {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like share_lib_zoneinfo_bad "
    strings:
        $ = "usr/share/lib/zoneinfo/bad" ascii wide
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
rule SUSP_Macho_Usr_Ref_share_zoneinfo {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like share_zoneinfo "
    strings:
        $ = "usr/share/zoneinfo/" ascii wide
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
rule SUSP_Macho_Usr_Ref_share_zoneinfo_EMULTIHOP {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like share_zoneinfo_EMULTIHOP "
    strings:
        $ = "usr/share/zoneinfo/EMULTIHOP" ascii wide
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
rule SUSP_Macho_Usr_Ref_tmp {
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-06"
        version = "1.0"
        description = "check Macho files for the reference to file under /usr/ like tmp "
    strings:
        $ = "usr/tmp" ascii wide
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

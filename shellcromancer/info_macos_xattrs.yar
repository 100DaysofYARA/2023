rule susp_macos_xattrs
{
	meta:
		description = "Identify macOS executables that manipulate extended attributes (xattr's)"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.03.13"
		DaysofYARA = "72/100"

	strings:
		$xattr_quarantine = "com.apple.quarantine"
		$xattr_macl = "com.apple.macl"
		$xattr_provenance = "com.apple.provenance"
		$xattr_sip = "com.apple.rootless"

		$allow_shipitsqrl = "SQRLShipIt"
		$allow_kbfs = "kbfs/libfuse.(*QuarantineXattrHandler)"
		$allow_goupdater = "go-updater/keybase.context.Apply"

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		uint32(0xc) == 0x2 and // mach_header->filetype == MH_EXECUTE
		any of ($xattr*) and
		not any of ($allow*)
}

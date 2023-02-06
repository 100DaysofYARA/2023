
rule macho_bad_entitlements
{
	meta:
		description = "Identify security related entitlement strings in Mach-o files, only in the entitlement blob."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.06"
		reference = "https://developer.apple.com/documentation/security/hardened_runtime"
		DaysofYARA = "37/100"

	strings:
		$cs_magic = { fa de 0c 00 } private
		$cs_magic_entitlement = { fa de 71 7? } private

		$s1 = "com.apple.security.cs.allow-unsigned-executable-memory"
		$s2 = "com.apple.security.cs.disable-library-validation"
		$s3 = "com.apple.security.cs.allow-jit"
		$s4 = "com.apple.security.automation.apple-events"
		$s5 = "com.apple.security.cs.allow-dyld-environment-variables"
		$s6 = "com.apple.security.cs.disable-executable-page-protection"
		$s7 = "com.apple.security.cs.debugger"

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		all of ($cs_magic*) and

		for any i in (1 .. #cs_magic_entitlement) : (
			any of ($s*) in ((@cs_magic_entitlement[i] + 8) .. @cs_magic_entitlement[i] + 8 + uint32be(@cs_magic_entitlement[i] + 4))
		)
}

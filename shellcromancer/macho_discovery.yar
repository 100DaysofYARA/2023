private rule file_macho
{
	meta:
		description = "Identify a mach-o binary abusing injection mechanisms."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.15"
		DaysofYARA = "15/100"

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
}

rule macho_discovery_imports
{
	meta:
		description = "Identify a mach-o binary abusing injection mechanisms."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.15"
		DaysofYARA = "15/100"
		reference = "https://github.com/cedowens/SwiftBelt/blob/master/Sources/SwiftBelt/main.swift"

	strings:
		$s1 = "NSProcessInfo" ascii fullword // Environment Variable listing
		$s2 = "NSUserName" ascii fullword
		$s3 = "NSHomeDirectory" ascii fullword
		$s4 = "NSUserDefaults" ascii fullword
		$s5 = "NSWorkspace" ascii fullword                    // Process listing
		$s6 = "sysctlbyname" ascii fullword                   // Kernel & Hostname listing
		$s7 = "CGSessionCopyCurrentDictionary" ascii fullword // Screen Lock Status
		$s8 = "NSPasteboard" ascii fullword                   // Clipboard listing
		$s9 = "AXIsProcessTrusted" ascii fullword             // TCC Trust Level listing

	condition:
		file_macho and
		40% of them
}


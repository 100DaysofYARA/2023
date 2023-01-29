private rule file_macho
{
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

rule macho_ui_swiftui
{
	meta:
		description = "Identify *OS executable built w/ SwiftUI"
		author = "@shellcromancer"
		version = "0.1"
		date = "2023.01.28"
		reference = "https://blog.timac.org/2022/0818-state-of-appkit-catalyst-swiftui-mac/"
		DaysofYARA = "28/100"

	strings:
		$framework = "/System/Library/Frameworks/SwiftUI.framework/Versions/A/SwiftUI"
		$symbol = "s7SwiftUI3AppPAAE4mainyyFZ"
	condition:
		file_macho and
		any of them
}

rule macho_ui_appkit
{
	meta:
		description = "Identify *OS executable built w/ AppKit"
		author = "@shellcromancer"
		version = "0.1"
		date = "2023.01.28"
		reference = "https://blog.timac.org/2022/0818-state-of-appkit-catalyst-swiftui-mac/"
		DaysofYARA = "28/100"

	strings:
		$framework = "/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit"
		$symbol = "NSApplicationMain"
	condition:
		file_macho and
		any of them
}

rule macho_ui_catalyst
{
	meta:
		description = "Identify *OS executable built w/ Mac Catalyst"
		author = "@shellcromancer"
		version = "0.1"
		date = "2023.01.28"
		reference = "https://blog.timac.org/2022/0818-state-of-appkit-catalyst-swiftui-mac/"
		DaysofYARA = "28/100"

	strings:
		$framework = "/System/iOSSupport/System/Library/Frameworks/UIKit.framework/Versions/A/UIKit"
		$symbol = "NSApplicationMain"
	condition:
		file_macho and
		any of them
}


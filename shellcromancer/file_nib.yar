rule file_nib
{
	meta:
		description = "Identify Apple NeXTSTEP Interface Builder files (.nib)"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.14"
		reference = "https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/LoadingResources/CocoaNibs/CocoaNibs.html"
		DaysofYARA = "45/100"

	strings:
		$bplist = { 62 70 6C 69 73 74 3? 3? }

		$s0 = "NSNib"
		$s1 = "NSView"
		$s2 = "NSTitle"
		$s3 = "UIView"
		$s4 = "NSSource"
		$s5 = "NSDestination"
		$s6 = "IB.objectdata"


	condition:
		$bplist at 0 and
		40% of ($s*)
}

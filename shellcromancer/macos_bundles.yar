import "macho"

rule macos_bundle_qlgenerator
{
	meta:
		description = "Identify macOS QuickLook plugins - a macOS persistence vector."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.15"
		reference = "https://theevilbit.github.io/beyond/beyond_0012/"
		DaysofYARA = "46/100"

	strings:
		$factory = "QuickLookGeneratorPluginFactory"

	condition:
		$factory and
		(
			macho.filetype == macho.MH_BUNDLE or
			for any file in macho.file : (
				file.filetype == macho.MH_BUNDLE
			)
		)
}

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

rule macos_bundle_mdimporter
{
	meta:
		description = "Identify macOS Spotlight Importers - a macOS persistence vector."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.16"
		reference = "https://theevilbit.github.io/beyond/beyond_0011/"
		DaysofYARA = "47/100"

	strings:
		$factory = "MetadataImporterPluginFactory"

	condition:
		$factory and
		(
			macho.filetype == macho.MH_BUNDLE or
			for any file in macho.file : (
				file.filetype == macho.MH_BUNDLE
			)
		)
}

rule macos_bundle_saver
{
	meta:
		description = "Identify macOS Screen Savers - a macOS persistence vector."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.17"
		reference = "https://theevilbit.github.io/beyond/beyond_0016/"
		reference = "https://posts.specterops.io/saving-your-access-d562bf5bf90b"
		DaysofYARA = "48/100"

	strings:
		$init1 = "initWithFrame"
		$init2 = "configureSheet"
		$init3 = "hasConfigureSheet"
		$init4 = "startAnimation"

	condition:
		3 of them and
		(
			macho.filetype == macho.MH_BUNDLE or
			for any file in macho.file : (
				file.filetype == macho.MH_BUNDLE
			)
		)
}

rule macos_bundle_colorpicker
{
	meta:
		description = "Identify macOS Color Picker's - a macOS persistence vector."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.18"
		reference = "https://theevilbit.github.io/beyond/beyond_0017/"
		DaysofYARA = "49/100"

	strings:
		$init1 = "NSColorPicker"
		$init2 = "NSColorPickingCustom"

	condition:
		all of them and
		(
			macho.filetype == macho.MH_BUNDLE or
			for any file in macho.file : (
				file.filetype == macho.MH_BUNDLE
			)
		)
}

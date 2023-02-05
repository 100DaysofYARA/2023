import "console"
import "hash"

private rule macho_entitlehash
{
	meta:
		description = "Identify code signed entitlements in Mach-o files, then hash them"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.05"
		DaysofYARA = "36/100"

	strings:
		$cs_magic = { fa de 0c 00 } private
		$cs_magic_entitlement = { fa de 71 71 } private

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		all of them and
		/*
			Entitlements XML stored in:
			@cs_magic_entitlement + 8 -> @cs_magic_entitlement + uint32be(@cs_magic_entitlement+4)
		*/
		for any i in (1 .. #cs_magic_entitlement) : (
			console.log(
				"Entitlehash: ",
				hash.md5(
					@cs_magic_entitlement[i] + 8,
					@cs_magic_entitlement[i] + uint32be(@cs_magic_entitlement[i] + 4)
				)
			)
		)
}

rule macho_entitlehash_check
{
	meta:
		description = "Identify a specific entitlehash"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.05"
		DaysofYARA = "36/100"

	strings:
		$cs_magic = { fa de 0c 00 } private
		$cs_magic_entitlement = { fa de 71 71 } private

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		all of them and
		for any i in (1 .. #cs_magic_entitlement) : (
			hash.md5(
				@cs_magic_entitlement[i] + 8,
				@cs_magic_entitlement[i] + uint32be(@cs_magic_entitlement[i] + 4)
			) == "7332589bceacb1d5553a77903020d63f"

		)
}

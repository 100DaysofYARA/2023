rule lang_nim
{
	meta:
		desc = "Identify a Nim binary regardless of format (PE, Macho, ELF) or arch."
		author = "@shellcromancer"
		version = "1.0"
		last_modified = "2023.01.03"
		sample = "8ec44187e50c15a7c4c89af4a1e99c63c855539101ec1ef4588d2e12e05f7d2b" // NimGrabber

	strings:
		$nim = "@nim"

	condition:
		(
			int16(0) == 0x5a4d or      // PE
			uint32(0) == 0x464c457f or // ELF
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		#nim > 4
}

rule tool_nimplant
{
	meta:
		description = "Identify the Nimplan binary based off strings in their blog."
		author = "@shellcromancer <root@shellcromancer.io>"
		version = "0.1"
		date = "2023-01-03"
		reference = "https://casvancooten.com/posts/2021/08/building-a-c2-implant-in-nim-considerations-and-lessons-learned/#introducing-nimplant---a-lightweight-implant-and-c2-framework"
	strings:
		$name = "nimplant" nocase

		$str0 = "Invalid number of arguments received. Usage: 'reg [query|add] [path] <optional: key> <optional: value>'"
		$str1 = "Invalid registry. Only 'HKCU' and 'HKLM' are supported"
		$str2 = "Unknown reg command. Please use 'reg query' or 'reg add' followed by the path (and value when adding a key)."
		$str3 = "Invalid number of arguments received. Usage: 'upload [local file] [optional: remote file]'."
		$str4 = "Something went wrong uploading the file (Nimplant did not receive response from staging server '"
	condition:
		lang_nim and
		(
			$name or
			3 of ($str*)
		)
}

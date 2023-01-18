rule file_wasm
{
	meta:
		description = "Identify WebAssembly programs in the binary format."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.17"
		reference = "https://webassembly.github.io/spec/core/binary/index.html"
		sample = "76d82df3b491016136cdc220a0a9e8f686f40aa2"
		DaysofYARA = "17/100"

	strings:
		$head = { 00 61 73 6D 01 00 00 00 }

	condition:
		$head at 0
}

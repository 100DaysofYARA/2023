import "elf"

rule elf_invalid_version {
    meta:
        desc = "Identify ELF file that has mangled header info."
        author = "@shellcromancer"
        version = "0.1"
        last_modified = "2023.01.01"
		reference = "https://n0.lol/ebm/1.html"
		reference = "https://tmpout.sh/1/1.html"
		hash = "05379bbf3f46e05d385bbd853d33a13e7e5d7d50"
    condition:
        (
			uint32(0) == 0x464c457f
			and uint8(0x6) > 1 // ELF Version is greater value than in spec.
		)
}

rule elf_early_entry {
    meta:
        desc = "Identify ELF file who's entrypoint is within the header."
        author = "@shellcromancer"
        version = "0.1"
        last_modified = "2023.01.02"
		reference = "https://n0.lol/ebm/1.html"
		reference = "https://tmpout.sh/1/1.html"
		hash = "05379bbf3f46e05d385bbd853d33a13e7e5d7d50"
    condition:
        (
			uint32(0) == 0x464c457f and
			not defined elf.entry_point
		)
}
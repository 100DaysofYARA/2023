rule hacktool_ezuri
{
	meta:
		description = "Identify an ELF executable written packed with the Ezuri crypter."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.02"
		reference = "https://www.guitmz.com/linux-elf-runtime-crypter/"
		reference = "https://github.com/guitmz/ezuri"
		sample = "ddbb714157f2ef91c1ec350cdf1d1f545290967f61491404c81b4e6e52f5c41f"
		DaysofYARA = "33/100"

	strings:
		$memfd_self = "/proc/self/fd/%d"
		$output = "/dev/null"

		$sym1 = "runFromMemory" // stub/main.go
		$sym2 = "aesDec"        // stub/main.go
		$sym3 = "procName"      // stub/vars.go

	condition:
		uint32(0) == 0x464c457f and // and // ELF
		all of them
}


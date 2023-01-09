rule head_xar
{
	meta:
		description = "Identify Apple eXtensible ARchive files (.xar, .pkg, .safariextz, .xip, etc)."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.09"
		reference = "https://github.com/apple-oss-distributions/xar"
		DaysofYARA = "9/100"

	condition:
		uint32be(0) == 0x78617221
}

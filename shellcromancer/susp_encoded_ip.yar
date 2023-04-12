rule susp_encoded_ip
{
	meta:
		description = "Identify encoded IP addresses - a form of obfuscation"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.24"
		DaysofYARA = "55/100"

	strings:
		$hex = /https?:\/\/0x[0-9A-Fa-f]+/
		$oct = /https?:\/\/0\d{3}\.0\d{3}\.0\d{3}/

	condition:
		any of them
}

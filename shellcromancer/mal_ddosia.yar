
rule mal_ddosia_go_stresser_client
{
	meta:
		description = "Identify the ddosia/go_stresser client"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.27"
		sample = "7e1727e018a040920c4b4d573d2f4543733ed8e3f185a9596f8ba2c70029a2bb"
		DaysofYARA = "58/100"

	strings:
		$s1 = "client_id.txt"
		$s2 = "_go_stresser"
		$s3 = "\\$_\\d|\\$_\\d{2}"

	condition:
		all of them
}

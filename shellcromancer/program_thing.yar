rule program
{
	meta:
		description = "Identify programs string thing"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.03.16"
		DaysofYARA = "75/100"

	strings:
		$str = { 40 28 23 29 50 52 4F 47 52 41 4D 3A [0-20] 20 20 50 52 4F 4A 45 43 54 3A [0-20] 0A }

	condition:
		any of them
}

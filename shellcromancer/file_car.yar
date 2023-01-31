rule file_car
{
	meta:
		description = "Identify Apple Compiled Asset Record files (.car). Inspect contents with `assetutil -I`"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.30"
		reference = "https://blog.timac.org/2018/1018-reverse-engineering-the-car-file-format/"
		DaysofYARA = "30/100"

	strings:
		$bomstore = { 42 4F 4D 53 74 6F 72 65 }

		$block1 = "CARHEADER"
		$block2 = "EXTENDED_METADATA"
		$block3 = "KEYFORMAT"

		$tree1 = "FACETKEYS"
		$tree2 = "RENDITIONS"

	condition:
		$bomstore at 0 and
		all of them
}


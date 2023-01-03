rule MAL_PY_Dimorf
{
	meta:
		author = "Silas Cutler"
		description = "Detection for Dimorf ransomeware"
		date = "2023-01-03"
		version = "1.0"
		ref = "https://github.com/Ort0x36/Dimorf"

	strings:
		$func01 = "def find_and_encrypt"
		$func02 = "def check_os"
		
		$comment01 = "checks if the user has permission on the file."

		$misc01 = "log_dimorf.log"
		$misc02 = ".dimorf"


	condition:
		all of them
}

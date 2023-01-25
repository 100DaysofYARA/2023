
rule mal_rat_spark_macOS
{
	meta:
		description = "Identify the Spark RAT backdoor built for macOS"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.25"
		reference = "https://www.sentinelone.com/labs/dragonspark-attacks-evade-detection-with-sparkrat-and-golang-source-code-interpretation/"
		reference = "https://github.com/XZB-1248/Spark/"
		DaysofYARA = "25/100"

	strings:
		$mac1 = "SendAppleEventToSystemProcess"
		$mac2 = "CompatCGImageCreateCopyWithColorSpace"

		$b1 = "COMMON.BRIDGE_IN_USE"
		$b2 = "COMMON.DEVICE_NOT_EXIST"
		$b3 = "COMMON.DISCONNECTED"
		$b4 = "COMMON.INVALID_BRIDGE_ID"
		$b5 = "COMMON.INVALID_PARAMETER"
		$b6 = "COMMON.OPERATION_NOT_SUPPORTED"
		$b7 = "COMMON.RESPONSE_TIMEOUT"
		$b8 = "COMMON.UNKNOWN_ERROR"

		$c1 = "PING"
		$c2 = "OFFLINE"
		$c3 = "LOCK"
		$c4 = "LOGOFF"
		$c5 = "HIBERNATE"
		$c6 = "SUSPEND"
		$c7 = "RESTART"
		$c8 = "SHUTDOWN"
		$c9 = "SCREENSHOT"
		$c10 = "TERMINAL_INIT"
		$c11 = "TERMINAL_INPUT"
		$c12 = "TERMINAL_RESIZE"
		$c13 = "TERMINAL_PING"
		$c14 = "TERMINAL_KILL"
		$c15 = "FILES_LIST"
		$c16 = "FILES_FETCH"
		$c17 = "FILES_REMOVE"
		$c18 = "FILES_UPLOAD"
		$c19 = "FILE_UPLOAD_TEXT"
		$c20 = "PROCESSES_LIST"
		$c21 = "PROCESS_KILL"
		$c22 = "DESKTOP_INIT"
		$c23 = "DESKTOP_PING"
		$c24 = "DESKTOP_KILL"
		$c25 = "DESKTOP_SHOT"
		$c26 = "COMMAND_EXEC"

	condition:
		(
			uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
			uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
			uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
			uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
			uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
			uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		any of ($mac*) and
		any of ($b*) and
		any of ($c*)
}

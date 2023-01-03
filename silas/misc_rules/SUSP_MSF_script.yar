rule SUSP_MSF_script
{
	meta:
		author = "Silas Cutler"
		description = "Experimental detection for Metasploit resource scripts"
		date = "2023-01-02"
		version = "1.0"
		ref = "https://docs.rapid7.com/metasploit/resource-scripts/"
		DaysofYARA = "2/100"

	strings:
		$ = "use multi/handler" nocase
		$ = "set payload " nocase
		$ = "set lhost " nocase
		$ = "set lport " nocase
		$ = "set rhost " nocase
		$ = "set rport " nocase
		$ = "exploit" nocase		

	condition:
	 	2 of them and
		for all offset in (0..(filesize-1)): ( uint8(offset) < 127)
}




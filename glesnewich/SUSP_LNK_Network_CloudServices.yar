rule SUSP_LNK_Network_CloudServices_Discord
{
	meta:
		author = "Greg Lesnewich"
		description = "check for LNK files referencing a common Cloud Service - this may be used to download additional components"
		date = "2023-01-03"
		version = "1.0"
		DaysofYARA = "3/100"
	strings:
        $ = "cdn.discordapp.com" ascii wide
	condition:
		uint32be(0x0) == 0x4C000000 and
		1 of them
}

rule SUSP_LNK_Network_CloudServices_OneDrive
{
	meta:
		author = "Greg Lesnewich"
		description = "check for LNK files referencing a common Cloud Service - this may be used to download additional components"
		date = "2023-01-03"
		version = "1.0"
		DaysofYARA = "3/100"
	strings:
		$ = "onedrive.live.com" ascii wide
	condition:
		uint32be(0x0) == 0x4C000000 and
		1 of them
}

rule SUSP_LNK_Network_CloudServices_OneDrive_API
{
	meta:
		author = "Greg Lesnewich"
		description = "check for LNK files referencing a common Cloud Service - this may be used to download additional components"
		date = "2023-01-03"
		version = "1.0"
		DaysofYARA = "3/100"
	strings:
		$ = "api.live.com" ascii wide
	condition:
		uint32be(0x0) == 0x4C000000 and
		1 of them
}

rule SUSP_LNK_Network_CloudServices_GoogleDrive
{
	meta:
		author = "Greg Lesnewich"
		description = "check for LNK files referencing a common Cloud Service - this may be used to download additional components"
		date = "2023-01-03"
		version = "1.0"
		DaysofYARA = "3/100"
	strings:
		$ = "drive.google.com" ascii wide
	condition:
		uint32be(0x0) == 0x4C000000 and
		1 of them
}

rule SUSP_LNK_Network_CloudServices_GoogleDocs
{
	meta:
		author = "Greg Lesnewich"
		description = "check for LNK files referencing a common Cloud Service - this may be used to download additional components"
		date = "2023-01-03"
		version = "1.0"
		DaysofYARA = "3/100"
	strings:
		$ = "docs.google.com" ascii wide
	condition:
		uint32be(0x0) == 0x4C000000 and
		1 of them
}

rule SUSP_LNK_Network_CloudServices_TransferSH
{
	meta:
		author = "Greg Lesnewich"
		description = "check for LNK files referencing a common Cloud Service - this may be used to download additional components"
		date = "2023-01-03"
		version = "1.0"
		DaysofYARA = "3/100"
	strings:
		$ = "transfer.sh" ascii wide
	condition:
		uint32be(0x0) == 0x4C000000 and
		1 of them
}


rule SUSP_LNK_Network_CloudServices_Discord_Mutations
{
	meta:
		author = "Greg Lesnewich"
		description = "check for LNK files referencing a common Cloud Service - this may be used to download additional components"
		date = "2023-01-03"
		version = "1.0"
		DaysofYARA = "3/100"
	strings:
        $discord_base64 = "discord" base64 base64wide
        $discord_xor = "discord" xor(0x01-0xff) ascii wide
        $discord_flipflop = "idcsrod" nocase ascii wide
    	$discord_reverse = "drocsid" nocase ascii wide
    	$discord_hex_enc_str = "646973636f7264" nocase ascii wide
    	$discord_decimal = "100 105 115 99 111 114 100" nocase ascii wide
    	$discord_fallchill = "wrhxliw" nocase ascii wide
    	$discord_stackpush = "hordhdisc" nocase ascii wide
    	$discord_stackpushnull = "hord\x00hdisc"
    	$discord_stackpushdoublenull = "hord\x00\x00hdisc"
	condition:
		uint32be(0x0) == 0x4C000000 and
		1 of them
}

rule SUSP_LNK_Network_CloudServices_OneDrive_Mutations
{
	meta:
		author = "Greg Lesnewich"
		description = "check for LNK files referencing a common Cloud Service - this may be used to download additional components"
		date = "2023-01-03"
		version = "1.0"
		DaysofYARA = "3/100"
	strings:
		$onedrive_base64 = "onedrive" base64 base64wide
        $onedrive_xor = "onedrive" xor(0x01-0xff) ascii wide
        $onedrive_flipflop = "nodeirev" nocase ascii wide
    	$onedrive_reverse = "evirdeno" nocase ascii wide
    	$onedrive_hex_enc_str = "6f6e656472697665" nocase ascii wide
    	$onedrive_decimal = "111 110 101 100 114 105 118 101" nocase ascii wide
    	$onedrive_fallchill = "lmvwirev" nocase ascii wide
    	$onedrive_stackpush = "hrivehoned" nocase ascii wide
    	$onedrive_stackpushnull = "hrive\x00honed"
    	$onedrive_stackpushdoublenull = "hrive\x00\x00honed"
	condition:
		uint32be(0x0) == 0x4C000000 and
		1 of them
}

rule SUSP_LNK_Network_CloudServices_OneDrive_API_Mutations
{
	meta:
		author = "Greg Lesnewich"
		description = "check for LNK files referencing a common Cloud Service - this may be used to download additional components"
		date = "2023-01-03"
		version = "1.0"
		DaysofYARA = "3/100"
	strings:
		$apilivecom_base64 = "api.live.com" base64 base64wide
        $apilivecom_xor = "api.live.com" xor(0x01-0xff) ascii wide
        $apilivecom_flipflop = "pa.iilevc.mo" nocase ascii wide
    	$apilivecom_reverse = "moc.evil.ipa" nocase ascii wide
    	$apilivecom_hex_enc_str = "6170692e6c6976652e636f6d" nocase ascii wide
    	$apilivecom_decimal = "97 112 105 46 108 105 118 101 46 99 111 109" nocase ascii wide
    	$apilivecom_fallchill = "akr.orev.xln" nocase ascii wide
    	$apilivecom_stackpush = "h.comhlivehapi." nocase ascii wide
    	$apilivecom_stackpushnull = "h.com\x00hlivehapi."
    	$apilivecom_stackpushdoublenull = "h.com\x00\x00hlivehapi."
	condition:
		uint32be(0x0) == 0x4C000000 and
		1 of them
}

rule SUSP_LNK_Network_CloudServices_GoogleDrive_Mutations
{
	meta:
		author = "Greg Lesnewich"
		description = "check for LNK files referencing a common Cloud Service - this may be used to download additional components"
		date = "2023-01-03"
		version = "1.0"
		DaysofYARA = "3/100"
	strings:
		$drivegooglecom_base64 = "drive.google.com" base64 base64wide
        $drivegooglecom_xor = "drive.google.com" xor(0x01-0xff) ascii wide
        $drivegooglecom_flipflop = "rdvi.eoggoelc.mo" nocase ascii wide
    	$drivegooglecom_reverse = "moc.elgoog.evird" nocase ascii wide
    	$drivegooglecom_hex_enc_str = "64726976652e676f6f676c652e636f6d" nocase ascii wide
    	$drivegooglecom_decimal = "100 114 105 118 101 46 103 111 111 103 108 101 46 99 111 109" nocase ascii wide
    	$drivegooglecom_fallchill = "wirev.tlltov.xln" nocase ascii wide
    	$drivegooglecom_stackpush = "h.comhoglehe.gohdriv" nocase ascii wide
    	$drivegooglecom_stackpushnull = "h.com\x00hoglehe.gohdriv"
    	$drivegooglecom_stackpushdoublenull = "h.com\x00\x00hoglehe.gohdriv"
	condition:
		uint32be(0x0) == 0x4C000000 and
		1 of them
}

rule SUSP_LNK_Network_CloudServices_GoogleDocs_Mutations
{
	meta:
		author = "Greg Lesnewich"
		description = "check for LNK files referencing a common Cloud Service - this may be used to download additional components"
		date = "2023-01-03"
		version = "1.0"
		DaysofYARA = "3/100"
	strings:
		$docsgooglecom_base64 = "docs.google.com" base64 base64wide
        $docsgooglecom_xor = "docs.google.com" xor(0x01-0xff) ascii wide
        $docsgooglecom_flipflop = "odscg.oolg.eocm" nocase ascii wide
    	$docsgooglecom_reverse = "moc.elgoog.scod" nocase ascii wide
    	$docsgooglecom_hex_enc_str = "646f63732e676f6f676c652e636f6d" nocase ascii wide
    	$docsgooglecom_decimal = "100 111 99 115 46 103 111 111 103 108 101 46 99 111 109" nocase ascii wide
    	$docsgooglecom_fallchill = "wlxh.tlltov.xln" nocase ascii wide
    	$docsgooglecom_stackpush = "hcomhgle.h.goohdocs" nocase ascii wide
    	$docsgooglecom_stackpushnull = "hcom\x00hgle.h.goohdocs"
    	$docsgooglecom_stackpushdoublenull = "hcom\x00\x00hgle.h.goohdocs"
	condition:
		uint32be(0x0) == 0x4C000000 and
		1 of them
}

rule SUSP_LNK_Network_CloudServices_TransferSH_Mutations
{
	meta:
		author = "Greg Lesnewich"
		description = "check for LNK files referencing a common Cloud Service - this may be used to download additional components"
		date = "2023-01-03"
		version = "1.0"
		DaysofYARA = "3/100"
	strings:
		$transfer_base64 = "transfer.sh" base64 base64wide
        $transfer_xor = "transfer.sh" xor(0x01-0xff) ascii wide
        $transfersh_flipflop = "rtnafsres.h" nocase ascii wide
    	$transfersh_reverse = "hs.refsnart" nocase ascii wide
    	$transfersh_hex_enc_str = "7472616e736665722e7368" nocase ascii wide
    	$transfersh_decimal = "116 114 97 110 115 102 101 114 46 115 104" nocase ascii wide
    	$transfersh_fallchill = "giamhuvi.hs" nocase ascii wide
    	$transfersh_stackpush = "h.shhsferhtran" nocase ascii wide
    	$transfersh_stackpushnull = "h.s\x00hhsferhtran"
    	$transfersh_stackpushdoublenull = "h.s\x00\x00hhsferhtran"
	condition:
		uint32be(0x0) == 0x4C000000 and
		1 of them
}

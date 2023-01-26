rule onenote_payload_inside_filedatastoreobject
{

meta:
	description = "OneNote Documents with suspicious payload content inside FileDataStoreObject"
	author = "Jeremy Brown (@alteredbytes)"
	version = "1.0"
	date = "2023.01.25"
	reference = "https://docs.fileformat.com/note-taking/one/"
	reference = "https://github.com/100DaysofYARA/2023/blob/215676cd2c05feef2b2c0a11855cda2e4ebcb23c/shellcromancer/file_one.yar"
	reference = "https://blog.didierstevens.com/2023/01/22/analyzing-malicious-onenote-documents/"

strings:

// OneNote GUID - {7B5C52E4-D88C-4DA7-AEB1-5378D02996D3)
$one_header = {E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29 96 D3}

// FileDataStoreObject Header GUID - {BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC}
$fdso_header = {E7 16 E3 BD 65 26 11 45 A4 C4 8D 4D 0B 7A 9E AC}

// FileDataStoreObject Footer GUID - {71FBA722-0F79-4A0B-BB13-899256426B24}
$fdso_footer = {22 A7 FB 71 79 0F 0B 4A BB 13 89 92 56 42 6B 24}

// HTA Content
$lure_vbscript_mime = "<script type=\"text/vbscript\">" nocase ascii
$lure_hta_app = "HTA:APPLICATION" nocase ascii

// Lure Content
$lure_click_to_view = "CLICK TO VIEW DOCUMENT" nocase ascii wide
$lure_double_click = "Double Click To View File" nocase ascii wide
$lure_open_document = "OPEN DOCUMENT" nocase ascii wide

// Scripting Content
$lure_vbs_autoopen = "Sub AutoOpen()" nocase ascii wide
$lure_wscript_shell = "WScript.Shell" nocase ascii wide
$lure_powershell = "powershell" nocase ascii wide
$lure_powershell_web_request = "Invoke-WebRequest" nocase ascii wide
$lure_powershell_filepath = "Start-Process -Filepath" nocase ascii wide

// PE Content
$lure_pe_header = {4D 5A 90 00}
$lure_pe_dos_string = "!This program cannot be run in DOS mode" ascii

condition:

	uint32be(0) == 0xE4525C7B and 
	$one_header at 0 and 
	$fdso_header and 
	$fdso_footer and
	for any i in (0..#fdso_header) : (
		for 2 of ($lure_*) : (
			(@fdso_header[i] < @) and (@ < @fdso_footer[i])
		) 
	)
}

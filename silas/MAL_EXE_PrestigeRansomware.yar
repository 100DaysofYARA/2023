import "pe"
rule MAL_EXE_PrestigeRansomware
{
	meta:
		author = "Silas Cutler"
		description = "Detection for Prestige Ransomware"
		date = "2023-01-04"
		version = "1.0"
		ref = "https://www.microsoft.com/en-us/security/blog/2022/10/14/new-prestige-ransomware-impacts-organizations-in-ukraine-and-poland/"
		hash = "5fc44c7342b84f50f24758e39c8848b2f0991e8817ef5465844f5f2ff6085a57"
		DaysofYARA = "4/100"

	strings:
		$ransom_email = "Prestige.ranusomeware@Proton.me" wide

		$ransom_message01 = "To decrypt all the data, you will need to purchase our decryption software." wide
		$ransom_message02 = "Contact us {}. In the letter, type your ID = {:X}." wide
		$ransom_message03 = "- Do not try to decrypt your data using third party software, it may cause permanent data loss." wide
		$ransom_message04 = "- Do not modify or rename encrypted files. You will lose them." wide

		$reg_ransom_note = "C:\\Windows\\System32\\reg.exe add HKCR\\enc\\shell\\open\\command /ve /t REG_SZ /d \"C:\\Windows\\Notepad.exe C:\\Users\\Public\\README\" /f" wide
	condition:
		uint16(0) == 0x5A4D and 
			(2 of them or pe.imphash() == "a32bbc5df4195de63ea06feb46cd6b55")
}

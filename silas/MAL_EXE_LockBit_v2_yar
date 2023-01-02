rule MAL_EXE_LockBit_v2
{
	meta:
		author = "Silas Cutler"
		description = "Detection for LockBit version 2.x from 2011"
		date = "2023-01-01"
		version = "1.0"
		hash = "00260c390ffab5734208a7199df0e4229a76261c3f5b7264c4515acb8eb9c2f8"
		DaysofYARA = "1/100"

	strings:
		$ransom_note01 = "that is located in every encrypted folder." wide
		$ransom_note02 = "Would you like to earn millions of dollars?" wide
		$ransom_note03 = "Our company acquire access to networks of various companies, as well as insider information that can help you steal the most valuable data of any company." wide
		$ransom_note04 = "You can provide us accounting data for the access to any company, for example, login and password to RDP, VPN, corporate email, etc. Open our letter at your email. Launch the provided virus on any computer in your company." wide
		$ransom_note05 = "Companies pay us the foreclosure for the decryption of files and prevention of data leak." wide
		$ransom_note06 = "You can communicate with us through the Tox messenger" wide
		$ransom_note07 = "Using Tox messenger, we will never know your real name, it means your privacy is guaranteed." wide
		$ransom_note08 = "If this contact is expired, and we do not respond you, look for the relevant contact data on our website via Tor or Brave Browser" wide

		$ransom_tox = "3085B89A0C515D2FB124D645906F5D3DA5CB97CEBEA975959AE4F95302A04E1D709C3C4AE9B7" wide
		$ransom_url = "http://lockbitapt6vx57t3eeqjofwgcglmutr3a35nygvokja5uuccip4ykyd.onion" wide

		$str1 = "Active:[ %d [                  Completed:[ %d" wide
		$str2 = "\\LockBit_Ransomware.hta" wide

	condition:
		uint16(0) == 0x5A4D and ( $ransom_tox or $ransom_url) and 2 of ($ransom_note*) and 1 of ($str*)
}

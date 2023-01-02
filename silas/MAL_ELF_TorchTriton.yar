rule MAL_ELF_TorchTriton
{
	meta:
		author = "Silas Cutler"
		description = "Detection for backdoor (TorchTriton) distributed with a nightly build of PyTorch"
		date = "2023-01-02"
		version = "1.0"
		hash = "2385b29489cd9e35f92c072780f903ae2e517ed422eae67246ae50a5cc738a0e"
		ref = "https://www.bleepingcomputer.com/news/security/pytorch-discloses-malicious-dependency-chain-compromise-over-holidays/"
		DaysofYARA = "2/100"

	strings:
		$error = "failed to send packet"
		$aes_key = "gIdk8tzrHLOM)mPY-R)QgG[;yRXYCZFU"
		$aes_iv = "?BVsNqL]S.Ni"

			// std::vector<std::__cxx11::basic_string<char> > splitIntoDomains(const string&, const string&, const string&)
		$func01 = "splitIntoDomains("
		$func02 = "packageForTransport"
		$func03 = "gatherFiles"
			// void sendFile(const string&, const string&, int, int, const string&)
		$func04 = "void sendFile("

		//enc Domain
		$domain = "&z-%`-(*"


	condition:
		uint32(0) == 0x464c457f and (
			(all of ($aes_*)) or
			(all of ($func*) and $error) or
			($domain and 2 of them)
			)
}

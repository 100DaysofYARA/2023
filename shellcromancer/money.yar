rule crypto
{
	meta:
		desc = "Identify cryptocurreny payment wallets"
		author = "@shellcromancer"
		version = "1.0"
		last_modified = "2023.01.06"

	strings:
		$btc_p2sh = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,39}\b/
		$btc_p2wpkh = /\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,59}\b/
		$monero = /\b4[0-9AB][0-9a-zA-Z]{93}|4[0-9AB][0-9a-zA-Z]{104}\b/
		$zcash = /\bzs[a-z0-9]{76}\b/
		$zcash_ua = /\bu1[a-z0-9]{211}\b/

	condition:
		any of them
}

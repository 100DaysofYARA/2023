include "file_wasm.yar"

rule wasm_coinminer
{
	meta:
		description = "Identify WebAssembly programs that perform cryptocurrency PoW operations."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.18"
		reference = "https://www.forcepoint.com/blog/x-labs/browser-mining-coinhive-and-webassembly"
		sample = "5117b6d9fd649e5946be0d3cbe4f285d14f64ca2"
		DaysofYARA = "18/100"
	strings:
		$s1 = "cryptonight"
		$s2 = "cryptonite"
		$s3 = "hashes per second"
		$s4 = "cn_slow_hash"

	condition:
		file_wasm and
		any of them
}

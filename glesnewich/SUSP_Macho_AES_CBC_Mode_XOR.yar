rule SUSP_Macho_AES_CBC_Mode_XOR
{
		meta:
			author = "Greg Lesnewich"
			date = "2023-01-18"
			version = "1.0"
			description = "check Macho files for what might be an AES XOR routine used in its CBC mode "

		strings:
			$aes_cbc_xor_movs = {0fb6480141304c1d010fb6480241304c1d020fb6480341304c1d030fb6480441304c1d040fb6480541304c1d050fb6480641304c1d060fb6480741304c1d070fb6480841304c1d080fb6480941304c1d090fb6480a41304c1d0a0fb6480b41304c1d0b0fb6480c41304c1d0c0fb6480d41304c1d0d0fb6480e41304c1d0e0fb6400f4130441d0f}
		condition:
			(uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
			1 of them
}

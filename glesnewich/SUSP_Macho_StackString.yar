rule SUSP_Macho_StackString_Library
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-18"
        version = "1.0"
        description = "check for the path /Library being passed as a stack string"
    strings:
        $slash_library = {4? ?? 2f 4c 69 62 72 61 72 79 4? } // /Library passed to stack with the register wildcarded
	$library = {4? ?? 4c 69 62 72 61 72 79 4? } // Library passed to stack with the register wildcarded
    condition:
        (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
	1 of them
}

rule SUSP_Macho_StackString_rmrf_Cmd
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-18"
        version = "1.0"
        description = "check for the string rm -rf being passed as a stack string"
    strings:
        $rm_rf_stack = {4? ?? 72 6d 20 2d 72 66 4? } // rm rf string passed to stack with the register wildcarded
    condition:
        (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
	1 of them
}

rule SUSP_Macho_StackString_UsersDir
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-18"
        version = "1.0"
        description = "check for the path /Users/ being passed as a stack string"
    strings:
        $users_dir = {4? ?? 2f 55 73 65 72 73 2f 4? } // /Users/ passed to stack with the register wildcarded
    condition:
        (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
	1 of them
}

rule SUSP_Macho_StackString_TAR
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-18"
        version = "1.0"
        description = "check for the string tar zxvf or just tar  being passed as a stack string"
    strings:
        $tar_zxvf = {4? ?? 74 61 72 20 7a 78 76 66 4? } // tar zxvf passed to stack with the register wildcarded
	$tar_zxf = {4? ?? 74 61 72 20 7a 78 66 4? }
    condition:
        (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
	1 of them
}


rule SUSP_Macho_StackString_chmod
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-18"
        version = "1.0"
        description = "check for the string chmod being passed as a stack string"
    strings:
        $chmod = {4? ?? 63 68 6d 6f 64 4? } // check for chmod being passed to the stack  with the register wildcarded
    condition:
        (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
	1 of them
}

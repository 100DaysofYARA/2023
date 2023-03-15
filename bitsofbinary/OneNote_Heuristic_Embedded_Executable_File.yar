rule Heuristic_OneNote_Notebook_with_Embedded_Executable_File {
    meta:
        author = "BitsOfBinary"
        description = "Detects OneNote notebooks with suspicious embedded executable files"
        reference = "https://interoperability.blob.core.windows.net/files/MS-ONE/%5bMS-ONE%5d.pdf"
        reference = "https://www.proofpoint.com/uk/blog/threat-insight/onenote-documents-increasingly-used-to-deliver-malware"
        version = "1.0"
        date = "2023-03-15"
        DaysofYARA = "74/100"

    strings:
        $embedded_file_container = {9B 1D 00 20}
        $embedded_file_name = {9C 1D 00 1C}
        
        $ext1 = ".ade" ascii wide nocase
        $ext2 = ".adp" ascii wide nocase
        $ext3 = ".ai" ascii wide nocase
        $ext4 = ".bat" ascii wide nocase
        $ext5 = ".chm" ascii wide nocase
        $ext6 = ".cmd" ascii wide nocase
        $ext7 = ".com" ascii wide nocase
        $ext8 = ".cpl" ascii wide nocase
        $ext9 = ".dll" ascii wide nocase
        $ext10 = ".exe" ascii wide nocase
        $ext11 = ".hlp" ascii wide nocase
        $ext12 = ".hta" ascii wide nocase
        $ext13 = ".inf" ascii wide nocase
        $ext14 = ".ins" ascii wide nocase
        $ext15 = ".isp" ascii wide nocase
        $ext16 = ".jar" ascii wide nocase
        $ext17 = ".js" ascii wide nocase
        $ext18 = ".jse" ascii wide nocase
        $ext19 = ".lib" ascii wide nocase
        $ext20 = ".lnk" ascii wide nocase
        $ext21 = ".mde" ascii wide nocase
        $ext22 = ".msc" ascii wide nocase
        $ext23 = ".msi" ascii wide nocase
        $ext24 = ".msp" ascii wide nocase
        $ext25 = ".mst" ascii wide nocase
        $ext26 = ".nsh" ascii wide nocase
        $ext27 = ".pif" ascii wide nocase
        $ext28 = ".ps" ascii wide nocase
        $ext29 = ".ps1" ascii wide nocase
        $ext30 = ".reg" ascii wide nocase
        $ext31 = ".scr" ascii wide nocase
        $ext32 = ".sct" ascii wide nocase
        $ext33 = ".shb" ascii wide nocase
        $ext34 = ".shs" ascii wide nocase
        $ext35 = ".sys" ascii wide nocase
        $ext36 = ".vb" ascii wide nocase
        $ext37 = ".vbe" ascii wide nocase
        $ext38 = ".vbs" ascii wide nocase
        $ext39 = ".vxd" ascii wide nocase
        $ext40 = ".wsc" ascii wide nocase
        $ext41 = ".wsf" ascii wide nocase
        $ext42 = ".wsh" ascii wide nocase

    condition:
        uint32be(0) == 0xE4525C7B and 
        $embedded_file_container and
        for any i in (1 .. #embedded_file_container) : (
            $embedded_file_name in (@embedded_file_container[i] .. @embedded_file_container[i] + 0x30) and
            any of ($ext*) in (@embedded_file_container[i] .. @embedded_file_container[i] + 0x100)
        )
}
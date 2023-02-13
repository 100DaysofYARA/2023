rule Stairwell_MaliciousOneNote
{
    strings:
        $header = { E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29 96 D3 }
        $file_datastore = { E7 16 E3 BD 65 26 11 45 A4 C4 8D 4D 0B 7A 9E AC }
        $susp_mz = "This program cannot be run in DOS mode"
        $susp_ps = "powershell.exe" nocase
        $susp_cmd1 = ".cmd" nocase
        $susp_cmd2 = "cmd.exe" nocase
        $susp_bat = ".bat" nocase
        $susp_hta1 = "mshta.exe" nocase
        $susp_hta2 = ".hta" nocase

    condition:
        ( $header at 0 ) and $file_datastore and ( any of ( $susp* ) )
}

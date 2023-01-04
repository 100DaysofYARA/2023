import "pe"

rule Heuristic_PE_PDB_Self_Identifying_as_Malware {
    meta:
        author = "BitsOfBinary"
        description = "Detects files that identify themselves as malware"
        reference = "https://bitsofbinary.github.io/yara/2023/01/04/100daysofyara-day-4.html"
        version = "1.0"
        date = "2023-01-04"
        DaysofYARA = "4/100"
        
    condition:
        pe.pdb_path icontains "malware"
}

rule SessionManager_IIS_Backdoor_PDB_Path_Segments {
    meta:
        author = "BitsOfBinary"
        description = "Detects the SessionManager IIS backdoor based on some unique PDB path segments"
        reference = "https://securelist.com/the-sessionmanager-iis-backdoor/106868/"
        reference = "https://bitsofbinary.github.io/yara/2023/01/04/100daysofyara-day-4.html"
        version = "1.0"
        date = "2023-01-04"
        DaysofYARA = "4/100"
        
    condition:
        pe.pdb_path contains "\\GodLike\\" or
        pe.pdb_path matches /\\t\\t[0-9]\\/ or
        pe.pdb_path endswith "\\sessionmanagermodule.pdb"
}
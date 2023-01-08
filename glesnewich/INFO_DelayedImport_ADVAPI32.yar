import "pe"

rule INFO_DelayedImport_ADVAPI32_Registry
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-08"
        version = "1.0"
        DaysofYARA = "8/100"

    condition:
        for any item in pe.delayed_import_details : (
            item.library_name == "ADVAPI32.dll" and for any api in item.functions:
            (
                api.name startswith "Reg"
                ) )
}


rule INFO_DelayedImport_ADVAPI32_Crypt
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-08"
        version = "1.0"
        DaysofYARA = "8/100"

    condition:
        for any item in pe.delayed_import_details : (
            item.library_name == "ADVAPI32.dll" and for any api in item.functions:
            (
                api.name startswith "Crypt"
                ) )
}

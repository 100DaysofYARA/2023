import "pe"

rule SUSP_Export_Offset_Zero
{
    meta:
        author = "Greg Lesnewich"
        description = "check for files that have at least 1 export that has an offset of 0"
        date = "2023-01-14"
        version = "1.0"
        DaysofYARA = "14/100"

    condition:
        for any exp in pe.export_details: (
            exp.offset == 0 and
            not defined exp.name  and
            not defined exp.forward_name
        )
}


rule SUSP_Export_Offset_Undefined
{
    meta:
        author = "Greg Lesnewich"
        description = "check for files that have at least 1 export that has an no defined offset or other fields"
        date = "2023-01-14"
        version = "1.0"
        DaysofYARA = "14/100"

    condition:
        for any exp in pe.export_details: (
            not defined exp.offset and
            not defined exp.name  and
            not defined exp.forward_name
        )
}

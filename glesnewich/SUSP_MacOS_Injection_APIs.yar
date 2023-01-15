rule SUSP_MacOS_Injection_API_NSLinkModule
{
    meta:
        author = "Greg Lesnewich"
        description = "basic string check for older dyld API's used for payload injection"
        date = "2023-01-15"
        reference = "https://blog.xpnsec.com/restoring-dyld-memory-loading/"
        reference = "https://twitter.com/patrickwardle/status/1547967373264560131"
        version = "1.0"
        DaysofYARA = "15/100"

    strings:
        $ = "NSLinkModule" nocase ascii wide
    condition:
        all of them
}


rule SUSP_MacOS_Injection_API_NSCreateObjectFileImageFromMemory
{
    meta:
        author = "Greg Lesnewich"
        description = "basic string check for older dyld API's used for payload injection"
        date = "2023-01-15"
        reference = "https://blog.xpnsec.com/restoring-dyld-memory-loading/"
        reference = "https://twitter.com/patrickwardle/status/1547967373264560131"
        version = "1.0"
        DaysofYARA = "15/100"

    strings:
        $ = "NSCreateObjectFileImageFromMemory" nocase ascii wide
    condition:
        all of them
}

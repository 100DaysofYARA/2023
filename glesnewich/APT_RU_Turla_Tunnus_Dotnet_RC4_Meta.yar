import "pe"
import "dotnet"

rule APT_RU_TurlaDaddy_Tunnus_Dotnet_RC4_Meta
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-06"
        reference = "https://www.mandiant.com/resources/blog/turla-galaxy-opportunity"
        version = "1.0"
        hash = "0fc624aa9656a8bc21731bfc47fd7780da38a7e8ad7baf1529ccd70a5bb07852"
        DaysofYARA = "6/100"


    condition:
        for any classy in dotnet.classes: (classy.name == "RC4Encryption") or

        for any item in dotnet.classes: ( for any meths in item.methods: (
            meths.name == "EncryptDecrypt"
            ))

}

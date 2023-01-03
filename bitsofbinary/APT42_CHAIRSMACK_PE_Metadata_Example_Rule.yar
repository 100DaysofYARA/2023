import "pe"
import "hash"

rule APT42_CHAIRSMACK_PE_Metadata {
    meta:
        author = "BitsOfBinary"
        description = "Detects samples of CHAIRSMACK based on unique PE metadata (i.e. imphash and rich PE header hash)"
        reference = "https://mandiant.com/resources/blog/apt42-charms-cons-compromises"
        reference = "https://bitsofbinary.github.io/yara/2023/01/03/100daysofyara-day-3.html"
        hash = "a37a290863fe29b9812e819e4c5b047c44e7a7d7c40e33da6f5662e1957862ab"
        version = "1.0"
        date = "2023-01-03"
        DaysofYARA = "3/100"

    condition:
        pe.imphash() == "72f60d7f4ce22db4506547ad555ea0b1" or 
        hash.md5(pe.rich_signature.clear_data) == "c0de41e45352714500771d43f0d8c4c3"
}
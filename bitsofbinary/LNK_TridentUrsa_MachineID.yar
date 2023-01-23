rule TridentUrsa_LNK_Machine_ID {
    meta:
        author = "BitsOfBinary"
        description = "Rule to pick up LNKs used by Gamaredon Group/Trident Ursa based on a unique MachineID"
        hash = "f119cc4cb5a7972bdc80548982b2b63fac5b48d5fce1517270db67c858e9e8b0"
        reference = "https://unit42.paloaltonetworks.com/trident-ursa/"
        reference = "https://github.com/pan-unit42/iocs/blob/master/Gamaredon/Gamaredon_IoCs_DEC2022.txt"
        reference = "https://bitsofbinary.github.io/yara/2023/01/23/100daysofyara-day-23.html"
        version = "1.0"
        date = "2023-01-23"
        DaysofYARA = "23/100"

    strings:
        $ = "desktop-farl139"
        
    condition:
        any of them
}
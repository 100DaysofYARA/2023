rule Emotet_LNK_Drive_Serial_May_2022 {
    meta:
        author = "BitsOfBinary"
        description = "Detects an LNK from May 2022 tagged as dropping Emotet based on a unique drive serial"
        hash = "b7d217f13550227bb6d80d05bde26e43cd752a870973052080a72a510c444b5a"
        reference = "https://bitsofbinary.github.io/yara/2023/01/13/100daysofyara-day-13.html"
        version = "1.0"
        date = "2023-01-13"
        DaysofYARA = "13/100"

    strings:
        $drive_serial = {11 38 85 1c}
    
    condition:
        uint32(0) == 0x0000004c and any of them
}
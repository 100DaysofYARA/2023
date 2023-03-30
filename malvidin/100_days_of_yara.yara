
rule days_of_yara_url_2byte
{
  meta:
    author = "malvidin"
    description = "Look for two byte xor of target string. Creating ~64K separate rules is faster (~12MB rule file)"
    warning = "Loops over entire file, very poor performance."
    target_string = "https://github.com/100DaysofYARA"
  condition:
    for any i in ( 0 .. filesize ) : (
        uint16be(i) ^ uint16be(i+2) == 0x1c04
        and not for 0x2dfc0 j in ( i+0, i+2, i+4, i+6, i+8, i+10, i+12, i+14, i+16, i+18, i+20, i+22, i+24, i+26, i+28 ) : ( 
            uint16be(j) ^ uint16be(j+2) 
        )
        and for 0x2dfbf j in ( i+0, i+2, i+4, i+6, i+8, i+10, i+12, i+14, i+16, i+18, i+20, i+22, i+24, i+26, i+28 ) : ( uint16be(j) ^ uint16be(j+2) )
    )
}

rule days_of_yara_url_3byte 
{
  meta:
    author = "malvidin"
    description = "Look for three byte xor of target string. Creating ~16M separate rules would probably be faster (~3.2 GB rule file)"
    warning = "Loops over entire file, very poor performance."
    target_string = "https://github.com/100DaysofYARA"
  condition:
    for any i in ( 0 .. filesize ) : ( 
      ( ( uint32be(i) ^ uint32be(i+3) ) >> 8 ) == 0x18074e
      and not for 0x1c4172e j in ( i+0, i+3, i+6, i+9, i+12, i+15, i+18, i+21, i+24 ) : ( 
        ( uint32be(j) ^ uint32be(j+3) ) >> 8 
      )
      and for 0x1c4172d j in ( i+0, i+3, i+6, i+9, i+12, i+15, i+18, i+21, i+24 ) : ( 
        ( uint32be(j) ^ uint32be(j+3) ) >> 8
      )
    )
}

rule days_of_yara_url_4byte 
{
  meta:
    author = "malvidin"
    description = "Look for four byte xor of target string. Creating ~4G separate rules would probably be faster (~860 GB rule file)"
    warning = "Loops over entire file, very poor performance."
    target_string = "https://github.com/100DaysofYARA"
  condition:
    for any i in ( 0 .. filesize ) : ( 
      uint32be(i) ^ uint32be(i+4) == 0x1b4e5b5f
      and not for 0x1248ee582 j in ( i+0, i+4, i+8, i+12, i+16, i+20, i+24 ) : ( 
        uint32be(j) ^ uint32be(j+4) 
      )
      and for 0x1248ee581 j in ( i+0, i+4, i+8, i+12, i+16, i+20, i+24 ) : ( 
        uint32be(j) ^ uint32be(j+4)
      )
    )
}

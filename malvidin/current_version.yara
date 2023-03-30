
rule current_version_2byte
{
  meta:
    author = "malvidin"
    description = "Look for two byte xor of target string. Creating ~64K separate rules is faster (~12MB rule file)"
    warning = "Loops over entire file, very poor performance."
    target_string = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
  condition:
    for any i in ( 0 .. filesize ) : (
        uint16be(i) ^ uint16be(i+2) == 0x351b
        and not for 0x2a153 j in ( i+0, i+2, i+4, i+6, i+8, i+10, i+12, i+14, i+16, i+18, i+20, i+22, i+24, i+26, i+28, i+30, i+32, i+34, i+36, i+38, i+40 ) : ( 
            uint16be(j) ^ uint16be(j+2) 
        )
        and for 0x2a152 j in ( i+0, i+2, i+4, i+6, i+8, i+10, i+12, i+14, i+16, i+18, i+20, i+22, i+24, i+26, i+28, i+30, i+32, i+34, i+36, i+38, i+40 ) : ( uint16be(j) ^ uint16be(j+2) )
    )
}

rule current_version_3byte 
{
  meta:
    author = "malvidin"
    description = "Look for three byte xor of target string. Creating ~16M separate rules would probably be faster (~3.2 GB rule file)"
    warning = "Loops over entire file, very poor performance."
    target_string = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
  condition:
    for any i in ( 0 .. filesize ) : ( 
      ( ( uint32be(i) ^ uint32be(i+3) ) >> 8 ) == 0x271807
      and not for 0x21267b9 j in ( i+0, i+3, i+6, i+9, i+12, i+15, i+18, i+21, i+24, i+27, i+30, i+33, i+36, i+39 ) : ( 
        ( uint32be(j) ^ uint32be(j+3) ) >> 8 
      )
      and for 0x21267b8 j in ( i+0, i+3, i+6, i+9, i+12, i+15, i+18, i+21, i+24, i+27, i+30, i+33, i+36, i+39 ) : ( 
        ( uint32be(j) ^ uint32be(j+3) ) >> 8
      )
    )
}

rule current_version_4byte 
{
  meta:
    author = "malvidin"
    description = "Look for four byte xor of target string. Creating ~4G separate rules would probably be faster (~860 GB rule file)"
    warning = "Loops over entire file, very poor performance."
    target_string = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
  condition:
    for any i in ( 0 .. filesize ) : ( 
      uint32be(i) ^ uint32be(i+4) == 0x240e1411
      and not for 0x113ecb50a j in ( i+0, i+4, i+8, i+12, i+16, i+20, i+24, i+28, i+32, i+36 ) : ( 
        uint32be(j) ^ uint32be(j+4) 
      )
      and for 0x113ecb509 j in ( i+0, i+4, i+8, i+12, i+16, i+20, i+24, i+28, i+32, i+36 ) : ( 
        uint32be(j) ^ uint32be(j+4)
      )
    )
}

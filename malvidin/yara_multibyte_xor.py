import re
from binascii import hexlify

input_1 = r'Software\Microsoft\Windows\CurrentVersion\Run'
input_2 = r'https://github.com/100DaysofYARA'


blank16 = '''
rule {title}_2byte
{{
  meta:
    author = "malvidin"
    description = "Look for two byte xor of target string. Creating ~64K separate rules is faster (~12MB rule file)"
    warning = "Loops over entire file, very poor performance."
    target_string = "{target_string}"

  strings:
    $target_string = /{target_escaped}/

  condition:
    not $target_string and
    for any i in ( 0 .. filesize ) : (
        uint16be(i) ^ uint16be(i+2) == {first_xor}
        and not for 0x{acccum_plus_one:x} j in ( {offsets} ) : ( 
            uint16be(j) ^ uint16be(j+2) 
        )
        and for 0x{accum:x} j in ( {offsets} ) : ( uint16be(j) ^ uint16be(j+2) )
    )
}}
'''

blank24 = '''
rule {title}_3byte 
{{
  meta:
    author = "malvidin"
    description = "Look for three byte xor of target string. Creating ~16M separate rules would probably be faster (~3.2 GB rule file)"
    warning = "Loops over entire file, very poor performance."
    target_string = "{target_string}"

  strings:
    $target_string = /{target_escaped}/

  condition:
    not $target_string and
    for any i in ( 0 .. filesize ) : ( 
      ( ( uint32be(i) ^ uint32be(i+3) ) >> 8 ) == {first_xor}
      and not for 0x{acccum_plus_one:x} j in ( {offsets} ) : ( 
        ( uint32be(j) ^ uint32be(j+3) ) >> 8 
      )
      and for 0x{accum:x} j in ( {offsets} ) : ( 
        ( uint32be(j) ^ uint32be(j+3) ) >> 8
      )
    )
}}
'''

blank32 = '''
rule {title}_4byte 
{{
  meta:
    author = "malvidin"
    description = "Look for four byte xor of target string. Creating ~4G separate rules would probably be faster (~860 GB rule file)"
    warning = "Loops over entire file, very poor performance."
    target_string = "{target_string}"

  strings:
    $target_string = /{target_escaped}/

  condition:
    not $target_string and
    for any i in ( 0 .. filesize ) : ( 
      uint32be(i) ^ uint32be(i+4) == {first_xor}
      and not for 0x{acccum_plus_one:x} j in ( {offsets} ) : ( 
        uint32be(j) ^ uint32be(j+4) 
      )
      and for 0x{accum:x} j in ( {offsets} ) : ( 
        uint32be(j) ^ uint32be(j+4)
      )
    )
}}
'''

d = {
    2: blank16,
    3: blank24,
    4: blank32,
}


def generate_rules(input_string, title, out_file=None):
    input_bytes = input_string.encode('utf-8')
    if len(input_bytes) < 12:
        print('input is not long enough')
        return
    if out_file is not None:
        with open(out_file, 'w') as yf:
            yf.write('')
    for i in (2, 3, 4):
        first = True
        first_xor = b''
        accum = 0
        last_offset = 0
        for j in range(0, len(input_bytes), i):
            if len(input_bytes[j + i:j + 2 * i]) < i:
                break
            xor_val = b'0x' + hexlify(bytes(a ^ b for a, b in zip(input_bytes[j:j + i], input_bytes[j + i:j + 2 * i])))
            if first:
                first = False
                first_xor = xor_val
            accum += int(xor_val, 16)
            last_offset = j
        yr = d[i].format(
            title=title,
            target_string=input_string.replace('\\', '\\\\'),
            target_escaped=re.escape(input_string).replace('/', '\\/'),
            first_xor=first_xor.decode('latin1'),
            accum=accum,
            acccum_plus_one=accum+1,
            string_len=last_offset,
            offsets=', '.join([f'i+{offset}' for offset in range(0, j, i)])
        )
        if out_file is None:
            print(yr)
        else:
            with open(out_file, 'a') as yf:
                yf.write(yr)


generate_rules(input_1, "current_version", 'current_version.yara')
generate_rules(input_2, "days_of_yara_url",  '100_days_of_yara.yara')

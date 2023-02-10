#!/usr/bin/env python3
import argparse
import sys
import yara
import glob

RULE = '''
import "pe"

rule Failed_Checksum {
	meta:
		description = "Did you know that 83% of malware has invalid checksums and 90% of legitimate files had valid checksums?"
		source = "https://practicalsecurityanalytics.com/pe-checksum/"
	condition:
		pe.checksum != pe.calculate_checksum()

}
'''

RULES = yara.compile(source=RULE)

def get_match_percentage(files):
    total = 0
    matched = []
    for f in files:
        try:
            d = open(f, 'rb').read()
            total += 1
            if RULES.match(data=d):
                 matched.append(f)
        except:
            continue

    return total, matched



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("clean_path", metavar="path", type=str,
                        help="Path to clean files; enclose in quotes, accepts * as wildcard for directories or files")
    parser.add_argument("malware_path", metavar="path", type=str,
                        help="Path to malware; enclose in quotes, accepts * as wildcard for directories or files")
    parser.add_argument("--matches", help="Flag to print matched files", action='store_true')

    args = parser.parse_args()
    clean_files = glob.glob(args.clean_path)
    mal_files = glob.glob(args.malware_path)
    c_total, c_matched = get_match_percentage(clean_files)
    m_total, m_matched = get_match_percentage(mal_files)
    print(f"[+] Clean files match percentage: {len(c_matched)}/{c_total} = {(len(c_matched)/c_total) * 100}%")
    print(f"[+] Dirty files match percentage: {len(m_matched)}/{m_total} = {(len(m_matched)/m_total) * 100}%")
    if(args.matches):
        print('[+] Clean matches:')
        for f in c_matched:
            print(f'\t{f}')
        print('[+] Malware matches:')
        for f in m_matched:
            print(f'\t{f}')
main()

#!/usr/bin/env python3
import argparse
import plyara
import re
import requests
import sys
import unicodedata
from bs4 import BeautifulSoup
from plyara.utils import rebuild_yara_rule
class WebPage:
    def __init__(self, url):
        self.content = ""
        self.rules = []
        self.url = url
        self.regex = re.compile(r"rule\s*(?:\S+?)(?:\s*?:.*?)?\s*{(?:.*?)\n\s*}", re.DOTALL)

        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:42.0) Gecko/20100101 Firefox/42.0',
                'Accept-Language': 'en-US,en',
                'Accept': 'text/html,application/xhtml+xml,application/xml',
                'Authority': 'www.google.com',
                'Upgrade-Insecure-Requests': '1',
            }
            self.content = requests.get(url, headers=headers).text
        except Exception as e:
            print(f'Error retrieving {url}:\n{e}\nexiting...')
            sys.exit(1)

    def get_rules(self):
        text = BeautifulSoup(self.content, "html.parser").get_text()
        rules = self.regex.findall(unicodedata.normalize("NFKD",text))
        parser = plyara.Plyara()
        for r in rules:
            try:
                parsed = parser.parse_string(r)
                for p in parsed:
                    p['metadata'].append({'scraped_from': self.url})
                #parsed['metadata']['scraped_from']
                self.rules += parsed
            except Exception as e:
                print(f'Error parsing "{r.split("{")[0]}":\n{e}')
                continue
        parser.clear()
        return([rebuild_yara_rule(r, condition_indents=True) for r in self.rules])

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Scrapes YARA rules from webpages')
    parser.add_argument('url', help='URL to scrape')
    args = parser.parse_args()

    print(args.url)
    page = WebPage(args.url)
    for r in page.get_rules():
        print(r)

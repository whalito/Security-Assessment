#!/usr/bin/python3
import argparse
from bs4 import BeautifulSoup
import os

def parse_xml(f,o):
    header = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun> 
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>                                                                                                                 
<nmaprun>                                                                                                                                                                                        
<scaninfo/>                    
<verbose/>                            
<debugging/>'''
    footer = '''<runstats>
<finished/>
<hosts/>
</runstats>
</nmaprun>'''
    print("[*] Nmap XML File:",f) 
    print("[*] Output Folder:",o)
    report = open (f,'r').read()
    soup = BeautifulSoup(report, 'lxml')
    hosts = soup.find_all('host')
    for host in hosts:
        soup2 = BeautifulSoup(str(host), 'lxml')
        hostname = soup2.address['addr']
        try:
            hostname = soup2.hostname['name']
        except:
            pass
        outfolder = o + '/' + hostname
        outfile = o + '/' + hostname + '/' + 'nmap.xml'
        try:
            os.mkdir(outfolder)
        except:
            pass
        xml = str(header) + str(host) + str(footer)
        try:
            file_ = open(outfile, 'w')
            file_.write(xml)
            file_.close()
        except:
            pass
    print('[*] Done Parsing..')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-x", "--nmapxml", help="Nmap XML file to parse")
    parser.add_argument("-o", "--output", help="output folder")
    args = parser.parse_args()
    if args.nmapxml is None and args.output is None:
        parser.print_help()
        parser.exit(1)
    parse_xml(args.nmapxml,args.output)
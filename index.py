from app.nessus.parser import NessusParser
import glob
from app.config import *
import argparse
import os

def parse(input_file, start=False, nmap=False, out=False):
    parser=NessusParser()
    files=glob.glob(input_file)
    parser.parse(files)
    filename=(out or 'export').replace('.xlsx', '').replace('.nmap', '')
    parser.createExcel(filename+'.xlsx')

    nmaptxt='# Nmap 7.92 scan initiated'
    for host in parser.hostwise.values():
        if not host['hostname']=='':nmaptxt+='Nmap scan report for {hostname} ({ip})'.format(hostname=host['hostname'], ip=host['address'])+'\n'
        else: nmaptxt+='Nmap scan report for {ip}'.format(ip=host['address'])+'\n'
        nmaptxt+='Host is up '+'\n'
        nmaptxt+='PORT    STATE    SERVICE      VERSION'+'\n'
        for port in host['ports'].values():
            nmaptxt+='{port}/{protocol}  open     {service}       {version}'.format(port=port['port'], protocol=port['protocol'], service=port['service'], version='')+'\n'
        if not host['mac']=='':nmaptxt+='MAC Address: {mac} ()'.format(mac=host['mac'])+'\n'
    if nmap:
        with open(filename+'.nmap', 'w') as f: f.write(nmaptxt)
        os.startfile(filename+'.nmap')
    if start:
        os.startfile(filename+'.xlsx')

parser=argparse.ArgumentParser(description="Parse and generate nessus and nmap output to report format...")
parser_g=parser.add_mutually_exclusive_group(required=True)
parser_g.add_argument('-r', '--recursive', help="using this optiosn will find and create excel recursively")
parser_g.add_argument('-iL', '--input-file', help='Parse nessus output and create excel')
parser.add_argument('-cN', '--create-nmap', action='store_true', help='Use this options tp create a nmap like text file from nessus output')
parser.add_argument('-O', '--out', action='store', help='Output File Name')
args=parser.parse_args()
# print(args)

if args.recursive:
    dirs=glob.glob(args.recursive)
    for folder in dirs:
        filename=folder.split('\\')[-1].split('/')[-1]
        parse(f'{folder}/*', nmap=args.create_nmap, start=False, out=f'{folder}/{filename}')

elif args.input_file:
    parse(args.input_file, nmap=args.create_nmap, start=True, out=args.out)
    
else: print()
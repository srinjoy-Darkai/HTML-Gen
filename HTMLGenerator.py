from fileinput import filename
import glob
import openpyxl
import os
import re
import shutil
import subprocess
import json
import argparse

class generator:
    def __init__(self):
        self.vulnerabilities={}
        self.hosts={}
        self.vulhostdb={}
        self.hostnames=[]
        self.sortby=0
        self.total=[0,0,0,0,0,0]
        self.output=False
    
    def parseExcel(self, file):
        print('Parsing Excel:',file)
        data=openpyxl.load_workbook(file).active
        for row in data.iter_rows(min_row=2, values_only=True):
            if row[2] is None:continue
            tempips=[]
            hosts=[]
            for host in row[2].split(','):
                # Nessus affected systems can include a service endpoint:
                # IP:hostname:port/protocol.  Split only the host identity
                # fields and retain the complete original value for output.
                endpoint=host.strip()
                host=endpoint.split(':', 2)
                if len(host)>=2 and host[0].strip() not in tempips:
                    hosts.append(host)
                    tempips.append(host[0].strip())
            
            def parseHosts():
                # pass
                if self.sortby:
                    return list(map(lambda x: x[1] if len(x[1].strip())>1 else x[0], hosts))
                else: return list(map(lambda x:x[0].strip(), hosts))

            vul_name=row[1].strip()
            vul_id=re.sub(r'[^\w]', '_', vul_name)
            if vul_id not in self.vulnerabilities and not vul_id=='TEMP':
                # print(row[len(row)-1])
                self.vulnerabilities[vul_id]={'id':vul_id,
                'name':vul_name,
                'hosts':[host.strip() for host in row[2].split(',') if len(host.strip().split(':', 2))>=2], 
                'cvss_score':row[4] if row[4] else 0, 
                'risk_factor':row[3] if row[3] else '', 
                'cvss_vector':row[5] if row[5] else '',
                'cvss_classification':list(map(lambda x: x.strip(), row[6].split(','))) if row[6] else [], 
                 'description':row[7], 
                 'impact':row[8], 
                 'remediation':row[9], 
                 'reference_links':[x.strip() for x in row[10].split(',')] if row[10] is not None else []}
            
            for host in hosts:
                address=host[0].strip()
                hostname=host[1].strip().upper()
                if address not in self.hosts:
                    self.hosts[address]={'address':address, 'hostname':hostname, 'open_ports':[], 'state':True, 'vulnerabilities':[], 'count':[0,0,0,0,0,0]}
                    if not hostname=='' and hostname not in self.hostnames:
                        self.hostnames.append(host[1].strip().upper())
                if vul_id=='TEMP' : continue
                vul={'name':self.vulnerabilities[vul_id]['name'], 'risk_factor':self.vulnerabilities[vul_id]['risk_factor'], 'cvss_score':self.vulnerabilities[vul_id]['cvss_score']}
                if not vul in self.hosts[address]['vulnerabilities']: self.hosts[address]['vulnerabilities'].append(vul)
                severity=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
                for risk in severity:
                    if risk in self.vulnerabilities[vul_id]['risk_factor'].upper():
                        self.hosts[address]['count'][severity.index(risk)]+=1
                        self.total[severity.index(risk)]+=1
                        self.total[5]+=1
                        self.hosts[address]['count'][5]+=1


    def parsenmaptxt(self, file):
        if os.path.getsize(file)/1024<2048:
            data=open(file, 'r').read()
            if 'Nmap scan report' in data:
                if 'REASON' in data: reg=r'(\d+)\/(tcp|udp)\s+(closed|open)\s+(\S+)(?:.*ttl \d+)(.*)?'
                else: reg=r'(\d+)\/(tcp|udp)\s+(closed|open)\s+(\S+)([^\n]+)?'
                hosts=data.split('Nmap scan rep')
                for host in hosts:
                    address=re.findall(r'ort for\s+(?:(.*?)\()?([\d\.]+)', host)
                    if len(address):
                        ip=address[0][1].strip()
                        hostname=address[0][0].strip()

                        not_matched=True
                        if not hostname=='':  
                            for nessus_host in self.hosts:
                                if hostname.upper()==self.hosts[nessus_host]['hostname'].upper(): 
                                    ip=self.hosts[nessus_host]['address']
                                    not_matched=False
                                    break
                            
                        if not_matched:
                            if ip not in self.hosts:
                                self.hosts[ip]={'address':ip, 'state':'Host is up' in host, 'hostname':'', 'vulnerabilities':[], 'open_ports':[], 'count':[0,0,0,0,0,0]}
                                mac=re.findall(r'[A-Z0-9]{2}:[A-Z0-9]{2}:[A-Z0-9]{2}:[A-Z0-9]{2}:[A-Z0-9]{2}:[A-Z0-9]{2}', host)
                                self.hosts[ip]['mac']=mac[0] if len(mac) else ''

                        if self.hosts[ip]['hostname'].upper()=='':self.hosts[ip]['hostname']=hostname
                        mac=re.findall(r'[A-Z0-9]{2}:[A-Z0-9]{2}:[A-Z0-9]{2}:[A-Z0-9]{2}:[A-Z0-9]{2}:[A-Z0-9]{2}', host)
                        if not 'mac' in self.hosts[ip] or self.hosts[ip]['mac']=='':self.hosts[ip]['mac']=mac[0] if len(mac) else False
                        self.hosts[ip]['open_ports']+=re.findall(reg, host)
                        temp_ports_check=[]
                        tmp_ports=[]
                        for port in self.hosts[ip]['open_ports']:
                            if not port[0]+port[1] in temp_ports_check:
                                temp_ports_check.append(port[0]+port[1])
                                tmp_ports.append(port)
                        self.hosts[ip]['open_ports']=tmp_ports
                        

    def createjson(self, out, start=True):
        def sortvul(vul):
            risks=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL', 'INFO']
            if vul['risk_factor'].upper() in risks:return risks.index(vul['risk_factor'].upper())
            else: return 0

        def sanitizeHost(host):
            host=self.hosts[host]
            host['vulnerabilities']=sorted(host['vulnerabilities'], key=lambda x: float(x['cvss_score']), reverse=True)
            host['vulnerabilities']=sorted(host['vulnerabilities'], key=sortvul)
            host['open_ports']=sorted(host['open_ports'], key=lambda x: x[0])
            return host

        # print(sanitizeHost(self.hosts.keys()[1]))

        hostwise=list(map(sanitizeHost, self.hosts))

        vulwise=sorted(self.vulnerabilities.values(), key=lambda x: self.vulnerabilities[x['id']]['cvss_score'], reverse=True)
        vulwise=sorted(vulwise, key=lambda x: x['risk_factor'])


        htmlfile=open('app/raw.html', 'r').read()
        
        filename=out or 'export'
        html_filename=filename.replace('.html', '')+'.html'
        with open(html_filename, 'w') as f: f.write(htmlfile.replace('{data}', json.dumps({'hosts':hostwise, 'vulnerabilities':vulwise, 'total':self.total})))
        try:
            word_filename=filename.replace('.docm', '')+'.docm'
            shutil.copyfile('app/base.docm', word_filename)
            if start: os.startfile(word_filename)
        except Exception as e: print(e)
        if start: os.startfile(html_filename)


def parse(nmap, excel, out, start=True):
    print('Generating',excel,out)
    # return
    nessus_files=[]
    nmap_files=[]
    if excel:
        for file in excel.split(','):nessus_files.extend(glob.glob(file))
    if nmap:
        for file in nmap.split(','):nmap_files.extend(glob.glob(file))

    parser=generator()

    for file in nessus_files:
        if file.endswith('.xlsx'): parser.parseExcel(file)
    for file in nmap_files:
        if file.endswith('.txt') or file.endswith('.nmap'): parser.parsenmaptxt(file)
    parser.createjson(out, start)



argparser=argparse.ArgumentParser(description="Generate HTML from excel and nmap files...")
argparser_g=argparser.add_mutually_exclusive_group(required=True)
argparser_g.add_argument('-r', '--recursive', help='Tell the parser to generate file recursively')
argparser_g.add_argument('--excel', help='Input excel filname or wildcard')
argparser.add_argument('-O','--out', help='output filename')
argparser.add_argument('--nmap', help='Input nmap filname or wildcard')

parsed_args=argparser.parse_args()

if parsed_args.nmap or parsed_args.excel:
    # print(parsed_args.nmap)
    parse(nmap=parsed_args.nmap, excel=parsed_args.excel, out=parsed_args.out or 'export', start=True)

elif parsed_args.recursive:
    dirs=glob.glob(parsed_args.recursive)
    for folder in dirs:
        filename=folder.split('\\')[-1].split('/')[-1]
        parse(nmap=f'{folder}/*', excel=f'{folder}/*', out=f'{folder}/{filename}', start=False)


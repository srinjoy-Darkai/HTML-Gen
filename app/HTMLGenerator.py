import glob
import os
import openpyxl
import re
import shutil
import json

class generator:
    def __init__(self):
        self.vulnerabilities={}
        self.hosts={}
        self.vulhostdb={}
        self.hostnames=[]
        self.sortby=0
        self.total=[0,0,0,0,0,0]
    
    def parseExcel(self, file):
        print('Parsing Excel:',file)
        data=openpyxl.load_workbook(file).active

        for row in data.iter_rows(min_row=2, values_only=True):
            if row[2]==None:continue
            tempips=[]
            hosts=[]
            for host in row[2].split(','):
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
                self.vulnerabilities[vul_id]={'id':vul_id,'name':vul_name,'hosts':[host.strip() for host in row[2].split(',') if len(host.strip().split(':', 2))>=2], 'cvss_score':row[4] if row[4] else 0, 'risk_factor':row[3] if row[3] else '', 'cvss_vector':row[5] if row[5] else '','cvss_classification':list(map(lambda x: x.strip(), row[6].split(','))) if row[6] else [], 'description':row[7], 'impact':row[8], 'remediation':row[9], 'reference_links':[x.strip() for x in row[10].split(',')] if row[10] else []}
            
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
                                continue
                                self.hosts[ip]={'address':ip, 'state':'Host is up' in host, 'hostname':'', 'vulnerabilities':[], 'open_ports':[], 'count':[0,0,0,0,0,0]}
                        
                        if self.hosts[ip]['hostname'].upper()=='':self.hosts[ip]['hostname']=hostname
                        self.hosts[ip]['open_ports']+=re.findall(reg, host)
                        temp_ports_check=[]
                        tmp_ports=[]
                        for port in self.hosts[ip]['open_ports']:
                            if not port[0]+port[1] in temp_ports_check:
                                temp_ports_check.append(port[0]+port[1])
                                tmp_ports.append(port)
                        self.hosts[ip]['open_ports']=tmp_ports
                        
                        



    def createjson(self):
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
        
        with open('output.html', 'w') as f: f.write(htmlfile.replace('{data}', json.dumps({'hosts':hostwise, 'vulnerabilities':vulwise, 'total':self.total})))
        try:
            shutil.copyfile('app/base.docm', 'export.docm')
            os.startfile('export.docm')
        except Exception as e: print(e)
        os.startfile('output.html')






# parser=generator()
# nessus_files=glob.glob(input('Enter Excel Filename(s) or Wildcard: '))
# # parser.sortby=1 if input("Do you want to show by hostnames?(y/n): ").upper()=='Y' else 0
# for file in nessus_files:
#     if file.endswith('.xlsx'): parser.parseExcel(file)

# nmap_files=glob.glob(input('Enter nmap Filename(s) or Wildcard: '))
# for file in nmap_files:
#     if file.endswith('.txt') or file.endswith('.nmap'): parser.parsenmaptxt(file)

# parser.createjson()

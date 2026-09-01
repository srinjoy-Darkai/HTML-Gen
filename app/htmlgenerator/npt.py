from app.nmap.parser import NmapParser
from app.htmlgenerator.npt_assets import *
import openpyxl
import glob
import os
import ipaddress
import shutil


class nptHTMLGenerator:
    def __init__(self):
        self.adtype=True if input('Type 1, if you want hosts to be defined by hostnames: ')==str('1') else False
        self.componentwise={}
        self.nessushostwise={}
        self.vulwise={}
        self.nmaphosts={}
        self.totalCount={'CRITICAL':0, 'HIGH':0, 'MEDIUM':0, 'LOW':0, 'INFO':0, 'TOTAL':0}

    @staticmethod
    def splitAffectedHost(host):
        """Split the Excel affected-system value: IP:hostname[:port/protocol]."""
        parts=host.strip().split(':', 2)
        address=parts[0].strip()
        hostname=parts[1].strip().upper() if len(parts)>1 else ''
        port=parts[2].strip() if len(parts)>2 else ''
        return address, hostname, port

    def nessusExcel(self, data):
        for row in data.iter_rows(min_row=2, values_only=True):
            if row[3]==None: continue
            if ',' in row[2]: hosts=row[2].split(',')
            elif ';' in row[2]: hosts=row[2].split(';')
            else : hosts=[row[2]]

            self.vulwise[row[1]]={'name':row[1], 'cvss_score':row[4] if row[4] else '', 'risk_factor':row[3] if row[3] else '', 'cvss_vector':row[5] if row[5] else '', 'hosts':[x.strip() for x in hosts], 'cvss_classification':row[6] if row[6] else '', 'description':row[7], 'impact':row[8], 'remediation':row[9], 'referrence_links':[x.strip() for x in row[10].split(',')] if row[10] else []}
            temphosts=[]
            for host in hosts:
                address, hostname, port=self.splitAffectedHost(host)
                # A finding may affect several ports on one host. Count the
                # vulnerability once for that host, while keeping every port
                # in the vulnerability-wise affected-systems list.
                if address in temphosts:continue
                host=address
                if host not in self.nessushostwise: 
                    self.nessushostwise[host]={'address':address, 'hostname':hostname, 'vulnerabilities':[], 'open_ports':[], 'state':True}
                    self.nessushostwise[host]['count']={'CRITICAL':0, 'HIGH':0, 'MEDIUM':0, 'LOW':0, 'INFO':0, 'TOTAL':0}
                if row[1]=='TEMP':continue
                for risk in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                    if risk in row[3].upper():
                        self.nessushostwise[host]['count'][risk]+=1
                        self.nessushostwise[host]['count']['TOTAL']+=1
                        self.totalCount[risk]+=1
                        self.totalCount['TOTAL']+=1
                self.nessushostwise[host]['vulnerabilities'].append({'name':row[1], 'cvss_score':row[4] if row[4] else '', 'risk_factor':row[3] if row[3] else ''})
                temphosts.append(address)

    def parse(self):
        nessusfiles=glob.glob(input("Input Nessus Excel .xlsx Filename(s)/Wildcard: "))
        for file in nessusfiles:
            if os.path.isfile(file) and file.endswith('.xlsx'):
                self.nessusExcel(openpyxl.load_workbook(file).active)

        nmapfiles=glob.glob(input("Input Nmap Filename(s)/Wildcard: "))
        for file in nmapfiles:
            if os.path.isfile(file) and file.endswith('.xml') or file.endswith('.txt') or file.endswith('.nmap'):
                parser=NmapParser()
                parser.parse(open(file, 'r', encoding='utf-8', errors='ignore').read())
                for host in parser.hosts.keys():
                    if host in self.nmaphosts:
                        if parser.hosts[host]['state']:continue
                    self.nmaphosts[host]=parser.hosts[host]

        self.merge()
        with open('app/htmlgenerator/npt.html', 'r')as f:
            data=f.read()
            with open('export.html', 'w')as g:
                data=data.replace('{componentwise}', self.componentwiseview())
                data=data.replace('{ipwise}', self.hostwisetable())
                data=data.replace('{vulwise}', self.vulwisetable())
                g.write(data)
        try: shutil.copy2('app/htmlgenerator/base.docm', 'export.docm')
        except:shutil.copy2('app/htmlgenerator/base.docm', 'export1.docm')
        try:os.startfile('export.docm')
        except: pass
        os.startfile('export.html')

    def merge(self):
        def ipcheck(ip):
            try: 
                ipaddress.ip_address(ip)
                return True
            except:return False

        for host in self.nmaphosts.items():
            if host[0] not in self.nessushostwise:
                self.nessushostwise[host[0]]=host[1]
            if self.nessushostwise[host[0]]['address']=='':host[1]['address']
            if self.nessushostwise[host[0]]['hostname']=='':host[1]['hostname']
            if 'count' not in self.nessushostwise[host[0]]:host[1]['count']={'CRITICAL':0, 'HIGH':0, 'MEDIUM':0, 'LOW':0, 'INFO':0, 'TOTAL':0}
            self.nessushostwise[host[0]]['state']=host[1]['state']
            self.nessushostwise[host[0]]['state']=True if self.nessushostwise[host[0]]['count']['TOTAL']>1 else host[1]['state']
            self.nessushostwise[host[0]]['open_ports']=host[1]['open_ports']
        
        self.nessushostwise=sorted(self.nessushostwise.items(), key=lambda x: ipaddress.IPv4Address(x[0]) if ipcheck(x) else x[1]['hostname'])
        self.nessushostwise=sorted(self.nessushostwise, key=lambda x: -1 if x[1]['state'] else 1)
    
    def componentwiseview(self):
        sl=1
        tempview=''
        for host in self.nessushostwise:
            if self.adtype:address=host[1]['address'] if host[1]['hostname']=='' else host[1]['hostname']
            else: address=host[1]['address']
            tempview+=VULTABLE_HOSTS.format(sl=sl, address=address, critical=host[1]['count']['CRITICAL'], high=host[1]['count']['HIGH'], medium=host[1]['count']['MEDIUM'], low=host[1]['count']['LOW'], info=host[1]['count']['INFO'], total=host[1]['count']['TOTAL'])
            sl+=1
        total=VULTABLE_TOTAL_COUNTS.format(critical=self.totalCount['CRITICAL'], high=self.totalCount['HIGH'], medium=self.totalCount['MEDIUM'], low=self.totalCount['LOW'], info=self.totalCount['INFO'], total=self.totalCount['TOTAL'])
        return VULTABLE.format(hosts=tempview, totalCounts=total)

    def hostwisetable(self):
        returndata=''
        j=1
        for host in self.nessushostwise:
            tempvularray=[]
            i=1
            hostadd='<b>HOSTNAME:</b>{host}'.format(host=host[1]['hostname']) if not host[1]['hostname']=='' else ''
            returndata+='<br><h3 class="list-level-1" style="text-decoration:none;">1.{sl}. <b>IP: </b>{address} {hostadd}</h3>'.format(address=host[1]['address'], sl=j, hostadd=hostadd)
            j+=1
            if host[1]['state']==True:
                if len(host[1]['vulnerabilities'])>1:
                    risk_factors={'CRITICAL':0, 'HIGH':0, 'MEDIUM':0, 'LOW':0, 'INFO':0, 'TOTAL':0}
                    for vul in host[1]['vulnerabilities']:
                        if vul['name']=='TEMP':continue
                        if risk_factors[vul['risk_factor'].upper()]<=0:
                            risk=HOST_VULTABLE_RISK_LEVEL.format(rowspan=host[1]['count'][vul['risk_factor'].upper()], risk_factor=vul['risk_factor'])
                            risk_factors[vul['risk_factor'].upper()]+=1
                        else: risk=''
                        tempvularray.append(HOST_VULTABLE_VULS.format(sl=i, name=vul['name'], risk=risk, cvss_score=vul['cvss_score']))
                        i+=1
                    vultable=HOST_VULTABLE.format(hosts=''.join(tempvularray))
                else: vultable=HOST_NO_VUL_FOUND
                returndata+=vultable
                if len(host[1]['open_ports'])>0:
                    tempports=''
                    for port in host[1]['open_ports']:
                        tempports+=HOST_OPEN_PORT_TABLE_PORTS.format(port=port['port'], protocol=port['protocol'], state=port['state'], service=port['service'], version=port['version'])
                    returndata+=HOST_OPEN_PORT_TABLE.format(ports=tempports)
                else: returndata+=HOST_NO_PORTS_FOUND
            else: returndata+=HOST_IS_DOWN
        return returndata

    def vulwisetable(self):
        returndata=''
        severities=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL', 'INFO']
        self.vulwise=sorted(self.vulwise.items(), key=lambda x: severities.index(x[1]['risk_factor'].upper()))
        i=1
        for vul in self.vulwise:
            def hostn(data):
                tempdata=[]
                for host in data:
                    address, hostname, port=self.splitAffectedHost(host)
                    if self.adtype:
                        if hostname!='': display=hostname
                        else: 
                            for thost in self.nessushostwise:
                                if thost[1]['address']==address:
                                    display=thost[1]['hostname'] if not thost[1]['hostname']=='' else address
                                    break
                            else: display=address
                    else: display=address
                    tempdata.append(display+(':'+port if port else ''))
                return ', '.join(tempdata)

            if vul[1]['name']=='TEMP':continue
            returndata+=VULWISE_TABLE.format(risk_factor=vul[1]['risk_factor'], sl=i, name=vul[1]['name'], cvss_score=vul[1]['cvss_score'], cvss_vector=vul[1]['cvss_vector'], cvss_classification=vul[1]['cvss_classification'], hosts=hostn(vul[1]['hosts']), description=vul[1]['description'], impact=vul[1]['impact'], remediation=vul[1]['remediation'], reference_links="<b>Reference Link:</b><br>"+'<br>'.join(map(lambda x: '<a style="font-size: 9pt" href="{link}">{link}</a>'.format(link=x), vul[1]['referrence_links'])) if len(vul[1]['referrence_links'])>0 else '')
            i+=1
        return returndata



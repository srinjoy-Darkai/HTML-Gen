from bs4 import BeautifulSoup
import xmltodict
import re
import json
import requests
import openpyxl
import os

def printf(data):print(data)

class NessusParser:
    def __init__(self):
        self.hostwise={}
        self.vulwise={}

    def parseHtml(self, data):
        soup = BeautifulSoup(data, 'lxml')
        host=''
        for i in soup.find_all('div'):
            if i.get('class') and 'table-wrapper' in i.get('class'):
                ip=i.find('td', string="IP:")
                if ip:
                    ip=ip.find_next_sibling().get_text().strip()
                    hostname=i.find('td', string="DNS Name:")
                    netbios=i.find('td', string="NETBIOS Name:")
                    mac=i.find('td', string="MAC Address:")

                    host=ip
                    name=hostname or netbios
                    print("Working on", host)
                    
                    if host not in self.hostwise:
                        self.hostwise[host]={'address':ip, 'hostname':name.find_next_sibling().get_text().strip().upper() if name is not None else '', 'mac':mac.find_next_sibling().get_text() if mac else '', 'vulnerabilities':['0'], 'ports':{}}
                    else: print(host)

            if host=='':continue
            if i.get('class') and 'section-wrapper' in i.get('class'): 
                port=i.find('h2').text.split('/')
                if len(port)==3 and port[0]+port[1] not in self.hostwise[host]['ports']:
                    self.hostwise[host]['ports'][port[0]+port[1]]={'port':port[1], 'protocol':port[0], 'service':port[2]}
                vuln=i.find_previous_sibling().get_text().split('-')[0].strip()
                if vuln not in self.hostwise[host]['vulnerabilities']: self.hostwise[host]['vulnerabilities'].append(vuln)
        
    def parseNessus(self, data):
        try:
            hosts=xmltodict.parse(data)['NessusClientData_v2']['Report']['ReportHost']
            for i in hosts:
                host=i['@name']
                if host not in self.hostwise: self.hostwise[host]={'address':host, 'vulnerabilities':['0']}
                for x in i['ReportItem']:
                    if x['@pluginID'] not in self.hostwise[host]['vulnerabilities']: self.hostwise[host]['vulnerabilities'].append(x['@pluginID'])
        except Exception as e: printf((e, 'hello'))

    def parse(self, files):
        for file in files:
            if os.path.isfile(file) and  file.endswith('.html'):
                print("parsing", file)
                self.parseHtml(open(file, 'r', errors='ignore').read())
        return self.hostwise
    
    def tovulwise(self, data=False):
        data = data if data else self.hostwise
        for host in data:
            for vul in self.hostwise[host]['vulnerabilities']:
                if vul not in self.vulwise: self.vulwise[vul]={'id':vul, 'hosts':[]}
                if host not in self.vulwise[vul]['hosts']: self.vulwise[vul]['hosts'].append(self.hostwise[host]['address']+":"+self.hostwise[host]['hostname'])
        return self.vulwise

    def getDetails(self, pluginid):
        pluginid=str(pluginid)
        if pluginid=='0':
            return {'id':pluginid, 'name':'TEMP', 'description':'', 'impact':'', 'remediation':'', 'referrence_links':[], 'cvss_score':'', 'cvss_vector':'', 'risk_factor':'Info', 'classifications':[]}
        try: 
            plugins=open('app/nessus/plugins.json', 'r').read()
            plugins=json.loads(plugins)
        except: plugins={}

        if pluginid in plugins: return plugins[pluginid]
        else: 
            try:
                printf('requesting data from api')
                details=requests.get('https://www.tenable.com/plugins/nessus/{}'.format(pluginid))
                # print(details.status_code)
                details=re.findall(r'<script id="__NEXT_DATA__".*?>(.*?)<\/script>', details.text, re.DOTALL)
                details=json.loads(details[0])['props']['pageProps']['plugin']
                plugin={'id':pluginid, 'name':details['script_name'], 'description':details['description'], 'impact':details['synopsis'], 'remediation':details['solution'] if 'solution' in details else '', 'referrence_links':details.get('see_also', '')}
                if details['cvss']:
                    plugin['cvss_score']=details['cvss']['cvssv3_score'] if details['cvss']['cvssv3_score'] else details['cvss']['cvssv2_score']
                    plugin['cvss_vector']=details['cvss']['cvssv3_vector'] if details['cvss']['cvssv3_vector'] else 'CVSS:2/'+details['cvss']['cvssv2_vector']
                    plugin['risk_factor']=details['cvss']['cvssv3_risk_factor'] if details['cvss']['cvssv3_risk_factor'] else details['cvss']['cvssv2_risk_factor']
                else:
                    plugin['cvss_score']=''
                    plugin['cvss_vector']=''
                    plugin['risk_factor']=details['risk_factor'] if details['risk_factor'] else details['severity']
                plugin['classifications']=list(map(lambda x: x['id_type']+'-'+x['id'], filter(lambda x: x['type']=='classifiers', details['references'])))+details['cves']
                plugins[pluginid]=plugin
            except Exception as e: 
                print(e, pluginid)
                return {}
            with open('app/nessus/plugins.json', 'w', errors='ignore') as f: f.write(json.dumps(plugins))
            return plugin


    def createExcel(self, filename=False):
        severities=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL', 'INFO']
        base=openpyxl.load_workbook('app/nessus/base.xlsx')
        wb=base.active
        checkProxy={}
        self.tovulwise()
        for vul in self.vulwise:
            self.vulwise[vul]['vuldata']=self.getDetails(self.vulwise[vul]['id'])
        self.vulwise=sorted(self.vulwise.items(), key=lambda x: x[1]['vuldata']['cvss_score'] if 'cvss_score' in x[1]['vuldata'] and not x[1]['vuldata']['cvss_score']=='' else 0, reverse=True)
        self.vulwise=sorted(self.vulwise, key=lambda x: severities.index(x[1]['vuldata']['risk_factor'].upper()))

        for vul in enumerate(self.vulwise):
            vuldata=vul[1][1]['vuldata']
            if vuldata['name']:
                row=str(vul[0]+2)
                wb['A'+row]=int(row)-1
                wb['B'+row]=vuldata['name']
                wb['C'+row]=', '.join(vul[1][1]['hosts'])
                wb['D'+row]=vuldata['risk_factor']
                wb['E'+row]=vuldata['cvss_score']
                wb['F'+row]=vuldata['cvss_vector']
                wb['G'+row]=', '.join(vuldata['classifications'])
                wb['H'+row]=vuldata['description']
                wb['I'+row]=vuldata['impact']
                wb['J'+row]=vuldata['remediation']
                wb['K'+row]=', '.join(vuldata['referrence_links'])
        filename=filename or 'export'
        base.save(filename)

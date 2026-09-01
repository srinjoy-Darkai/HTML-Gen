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

    def _add_vulnerability(self, host, plugin_id, port='', protocol=''):
        """Record a Nessus finding and the endpoint Nessus reported for it."""
        details = self.hostwise[host]
        plugin_id = str(plugin_id)
        if plugin_id not in details['vulnerabilities']:
            details['vulnerabilities'].append(plugin_id)

        # Nessus uses port 0 for host-level findings.  Do not present that as
        # a network service, but retain all real ports for a plugin/host pair.
        if str(port) in ('', '0', 'None'):
            return
        port_label = str(port)
        if protocol not in ('', None):
            port_label += '/' + str(protocol)
        ports = details.setdefault('vulnerability_ports', {}).setdefault(plugin_id, [])
        if port_label not in ports:
            ports.append(port_label)

    @staticmethod
    def _host_property(host_properties, *names):
        """Return the first non-empty Nessus HostProperties value by tag name."""
        if not host_properties:
            return ''
        tags = host_properties.get('tag', [])
        if not isinstance(tags, list):
            tags = [tags]
        requested_names = {name.lower() for name in names}
        for tag in tags:
            if not isinstance(tag, dict):
                continue
            if str(tag.get('@name', '')).lower() in requested_names:
                value = tag.get('#text', '')
                if value is not None and str(value).strip():
                    return str(value).strip()
        return ''

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
                        self.hostwise[host]={'address':ip, 'hostname':name.find_next_sibling().get_text().strip().upper() if name is not None else '', 'mac':mac.find_next_sibling().get_text() if mac else '', 'vulnerabilities':['0'], 'ports':{}, 'vulnerability_ports':{}}
                    else: print(host)

            if host=='':continue
            if i.get('class') and 'section-wrapper' in i.get('class'): 
                port=i.find('h2').text.split('/')
                if len(port)==3 and port[0]+port[1] not in self.hostwise[host]['ports']:
                    self.hostwise[host]['ports'][port[0]+port[1]]={'port':port[1], 'protocol':port[0], 'service':port[2]}
                vuln=i.find_previous_sibling().get_text().split('-')[0].strip()
                self._add_vulnerability(host, vuln, port[1] if len(port) > 1 else '', port[0] if port else '')
        
    def parseNessus(self, data):
        try:
            hosts=xmltodict.parse(data)['NessusClientData_v2']['Report']['ReportHost']
            if not isinstance(hosts, list):
                hosts=[hosts]
            for i in hosts:
                properties = i.get('HostProperties', {})
                # ReportHost/@name is not consistently an IP address.  Prefer
                # host-ip so affected systems retain the IP:FQDN:port format.
                host = self._host_property(properties, 'host-ip') or i['@name']
                hostname = self._host_property(properties, 'host-fqdn', 'hostname', 'netbios-name')
                if host not in self.hostwise:
                    self.hostwise[host]={'address':host, 'hostname':hostname.upper(), 'mac':'', 'vulnerabilities':['0'], 'ports':{}, 'vulnerability_ports':{}}
                elif hostname and not self.hostwise[host].get('hostname'):
                    self.hostwise[host]['hostname'] = hostname.upper()
                report_items=i.get('ReportItem', [])
                if not isinstance(report_items, list):
                    report_items=[report_items]
                for x in report_items:
                    self._add_vulnerability(host, x['@pluginID'], x.get('@port', ''), x.get('@protocol', ''))
        except Exception as e: printf((e, 'hello'))

    def parse(self, files):
        for file in files:
            file_type=os.path.splitext(file)[1].lower()
            if os.path.isfile(file) and file_type=='.html':
                print("parsing", file)
                self.parseHtml(open(file, 'r', errors='ignore').read())
            elif os.path.isfile(file) and file_type=='.nessus':
                print("parsing", file)
                self.parseNessus(open(file, 'r', errors='ignore').read())
        return self.hostwise
    
    def tovulwise(self, data=False):
        data = data if data else self.hostwise
        for host in data:
            for vul in self.hostwise[host]['vulnerabilities']:
                if vul not in self.vulwise: self.vulwise[vul]={'id':vul, 'hosts':[]}
                host_details=self.hostwise[host]
                base_host=host_details['address']+":"+host_details.get('hostname', '')
                ports=host_details.get('vulnerability_ports', {}).get(vul, [])
                affected_hosts=[base_host+":"+port for port in ports] if ports else [base_host]
                for affected_host in affected_hosts:
                    if affected_host not in self.vulwise[vul]['hosts']:
                        self.vulwise[vul]['hosts'].append(affected_host)
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
                print('[WARNING]:: key %s not found for PLUGIN:: %s in NESSUS API'%(e, pluginid))
                return {}
            with open('app/nessus/plugins.json', 'w', errors='ignore') as f: f.write(json.dumps(plugins))
            return plugin


    def createExcel(self, filename=False):
        def ss(x):
            try:return severities.index(x[1]['vuldata']['risk_factor'].upper())
            except: return 0

        severities=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL', 'INFO']
        base=openpyxl.load_workbook('app/nessus/base.xlsx')
        wb=base.active
        self.tovulwise()
        for vul in self.vulwise:
            self.vulwise[vul]['vuldata']=self.getDetails(self.vulwise[vul]['id'])
        self.vulwise=sorted(self.vulwise.items(), key=lambda x: x[1]['vuldata']['cvss_score'] if 'cvss_score' in x[1]['vuldata'] and not x[1]['vuldata']['cvss_score']=='' else 0, reverse=True)
        self.vulwise=sorted(self.vulwise, key=ss)

        for vul in enumerate(self.vulwise):
            vuldata=vul[1][1]['vuldata']
            if 'name' in vuldata:
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

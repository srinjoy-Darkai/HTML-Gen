from libnmap.parser import NmapParser as nmap
import re
import json

class NmapParser:
    def __init__(self):
        self.hosts={}

    def parseXML(self, data):
        try: 
            try: nmapdata=nmap.parse(data)
            except: nmapdata=nmap.parse(data, incomplete=True)
        except Exception as e: 
            print(e)
            return ''

        for host in nmapdata.hosts:
            address=host.address
            if address not in self.hosts or not self.hosts[address]['state'] and host.is_up():
                self.hosts[address]={'address':host.ipv4, 'hostname':host.hostnames[0].upper() if len(host.hostnames) else '', 'state':host.is_up(), 'vulnerabilities':[], 'open_ports':[]}
                if host.is_up():
                    for service in host.services:
                        if service.open():
                            self.hosts[address]['open_ports'].append({'port':service.port, 'protocol':service.protocol, 'state':service.state, 'service':service.service, 'version':service.banner.replace('product: ', '')})

    def parseTxt(self, data):
        tabstrings=re.findall(r'PORT\s+STATE.*', data)
        if not len(tabstrings): return ''
        self.tabstring={'port':{'start':tabstrings[0].find('PORT'), 'stop':tabstrings[0].find('STATE')-1}, 'state':{'start':tabstrings[0].find('STATE'), 'stop':tabstrings[0].find('SERVICE')-1}, 'service':{'start':tabstrings[0].find('SERVICE'), 'stop':tabstrings[0].find('REASON')-1 if 'REASON' in tabstrings[0] else tabstrings[0].find('VERSION')-1}, 'version':{'start':tabstrings[0].find('VERSION')}}
        
        hosts=data.split('Nmap scan re')
        for host in hosts:
            if 'port for' in host:
                address=re.findall(r'port for .*?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})', host)[0]
                hostnames=re.findall(r'port for (.*?)\(', host)
                if address not in self.hosts:
                    # continue
                    self.hosts[address]={'address':address, 'hostname':'', 'state':True if 'Host is up' in host else False, 'vulnerabilities':[], 'open_ports':[]}
                    if len(hostnames):self.hosts[address]['hostname']=hostnames[0].strip().upper()
                self.hosts[address]['state']=True if 'Host is up' in host else self.hosts[address]['state']
                for service in re.findall(r'\d+\/(?:tcp|udp)\s+open.*', host):
                    self.hosts[address]['open_ports'].append(self.parseServices(service))
    
    # def parseTxtRajdeep(self, data):
    #     hosts=data.split('Host No.')
    #     for host in hosts:
    #         if 'IP' in host:
    #             try:
    #                 address=re.findall(r'IP\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})', host)[0]
    #                 hostnames=re.findall(r'HOST(?:\s+|\t+)(.*)', host)
    #                 self.hosts[address]={'address':address, 'hostname':hostnames[0].strip().upper() if len(hostnames) else '', 'state':'', 'vulnerabilities':[], 'open_ports':[]}
    #                 # self.hosts[address]['state']=False if 'Host Unreachable' in host else True
    #                 self.hosts[address]['state']=False if 'Down' in host else True
    #                 for service in re.findall(r'(\d+)\/(tcp|udp)(?:\t+|\s+)(?:open)?(?:\t+|\s+)?(\S+)(.*)?', host):
    #                     self.hosts[address]['open_ports'].append({'port':service[0], 'protocol':service[1], 'state':'open', 'service':service[2], 'version':service[3] if len(service)>2 else ''})
    #             except: 
    #                 print(host)
    #                 break
    
    def parseServices(self, data):
        service={}
        service['port']=data[self.tabstring['port']['start']:self.tabstring['port']['stop']].strip().split('/')[0]
        service['protocol']=data[self.tabstring['port']['start']:self.tabstring['port']['stop']].strip().split('/')[1]
        service['state']=data[self.tabstring['state']['start']:self.tabstring['state']['stop']].strip()
        service['service']=data[self.tabstring['service']['start']:self.tabstring['service']['stop']].strip()
        service['version']=data[self.tabstring['version']['start']::].strip()
        return service

    def parse(self, data):
        if data.startswith('# Nmap') or 'Starting Nmap' in data or 'https://nmap.org' in data:
            self.parseTxt(data)
        elif data.startswith('<?xml ver'):
            self.parseXML(data)
        # elif 'Host No.' in data:
        #     self.parseTxtRajdeep(data)


# parser=NmapParser()
# nmapfile=open('internal_rest.nmap', 'r').read()
# parser.parseTxt(nmapfile)
# print(parser.hosts)
# with open('test.json', 'w') as f: f.write(json.dumps(parser.hosts))
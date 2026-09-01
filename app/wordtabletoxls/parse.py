import re
import json
import openpyxl

hostnames=[]
ips=[]

data=open('ssir.txt', 'r', errors='ignore').read()

hosts=data.split('Host No.')
hosts.pop(0)
for host in hosts:
    ip=re.findall(r'IP\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})', host)
    hostname=re.findall(r'HOST(?:\s+|\t+)(.*)', host)
    if len(ip):ips.append(ip[0].upper().strip())
    else: ips.append('')
    if len(hostname):hostnames.append(hostname[0].upper().strip())
    else: hostnames.append('')

wb_base=openpyxl.load_workbook('base.xlsx')
wb=wb_base.active
raw_vulnerabilities=data.split('Vulnerability Na')
raw_vulnerabilities.pop(0)
vularray=[]
i=0

def hostparse(data):
    data2=[]
    for host in data:
        host=host.strip().upper().replace(' ', '')
        if host in hostnames:
            data2.append(ips[hostnames.index(host)]+":"+host)
        elif host in ips:
            data2.append(host+":"+hostnames[ips.index(host)])
    return data2


for raw_vul in raw_vulnerabilities:
    if 'Vulnerability Rating:' not in raw_vul: continue
    # print(raw_vul)
    try:
        data={}
        data['name']=re.findall(r'^me:\s+?(.*)', raw_vul)[0]
        data['risk_factor']=re.findall(r'Rating:\s+?(.*)', raw_vul)[0]
        data['score']=re.findall(r'CVSS:(?:\s+)?([\d\.]+|N?)[\n\s]', raw_vul)[0]
        try: data['cvss']=re.findall(r'CVSS2?[:#][\d\.\/:A-Za-z]{5,}', raw_vul, re.MULTILINE)[0]
        except: data['cvss']=''
        data['cve']=re.findall(r'((?:CVE: \d{4}-\d+)|CWE: \d+)', raw_vul)
        data['hosts']=re.findall(r'Affecte.*:(.*?)Vulnerabi', raw_vul, re.DOTALL)[0].split(',')
        data['description']=re.findall(r'Description(?:\s+|\t+)?(.*?)Impact', raw_vul, re.DOTALL)[0].strip()
        data['impact']=re.findall(r'Impact(?:\s+|\t+)?(.*?)Remediation', raw_vul, re.DOTALL)[0].strip()
        data['remediation']=re.findall(r'Remediation(?:\s+|\t+)?(.*?)(?:References:|Proof)', raw_vul, re.DOTALL)[0].strip()
        try: data['reference_links']=[re.sub(r'\d+?.[\t\n\s]', '', x).strip() for x in re.findall(r'References:(.*?)Proof', raw_vul, re.DOTALL)[0].strip().split('\n')]
        except: data['reference_links']=[]
        vularray.append(data)
        row=str(i+2)
        wb['A'+row]=row
        wb['B'+row]=data['name']
        wb['C'+row]=', '.join(data['hosts'])
        wb['D'+row]=data['risk_factor']
        wb['E'+row]=data['score']
        wb['F'+row]=data['cvss']
        wb['G'+row]=', '.join(data['cve'])
        wb['H'+row]=data['description']
        wb['I'+row]=data['impact']
        wb['J'+row]=data['remediation']
        wb['K'+row]=', '.join(data['reference_links'])
        i+=1
    except Exception as e:
        print(e)
        print(raw_vul)
        break

row=str(i+2)
wb['A'+row]=row
wb['B'+row]="TEMP"
wb['C'+row]=', '.join(hostparse(ips))
wb['D'+row]="INFO"
wb['E'+row]=''
wb['F'+row]=''
wb['G'+row]=''
wb['H'+row]=''
wb['I'+row]=''
wb['J'+row]=''
wb['K'+row]=''
i+=1

with open('test.json', 'w', errors='ignore') as f: f.write(json.dumps(vularray))
wb_base.save('export.xlsx')
import re
import json
import openpyxl

data=open('test.txt', 'r', errors='ignore').read()
wb_base=openpyxl.load_workbook('base.xlsx')
wb=wb_base.active
raw_vulnerabilities=data.split('Vulnerability Na')
vularray=[]
i=0
for raw_vul in raw_vulnerabilities:
    if 'Vulnerability' not in raw_vul: continue
    # print(raw_vul)
    try:
        data={}
        data['name']=re.findall(r'^me:\s+?(.*)', raw_vul)[0]
        data['risk_factor']=re.findall(r'Rating:\s+?(.*)', raw_vul)[0]
        data['score']=re.findall(r'CVSS:\s?([\d\.]+?)[\n\s]', raw_vul)[0]
        try: data['cvss']=re.findall(r'CVSS2?[:#][\d\.\/:A-Za-z]{5,}', raw_vul, re.MULTILINE)[0]
        except: data['cvss']=''
        data['cve']=re.findall(r'(\w+-\d{4}-\d+)', raw_vul)
        data['hosts']=[x.strip() for x in re.findall(r'Affecte.*:(.*?)Vulnerabi', raw_vul, re.DOTALL)[0].split(',')]
        data['description']=re.findall(r'Description\s(.*?)Impact', raw_vul, re.DOTALL)[0].strip()
        data['impact']=re.findall(r'Impact\s(.*?)Remediation', raw_vul, re.DOTALL)[0].strip()
        data['remediation']=re.findall(r'Remediation\s(.*?)(?:References:|Proof)', raw_vul, re.DOTALL)[0].strip()
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
with open('test.json', 'w', errors='ignore') as f: f.write(json.dumps(vularray))
wb_base.save('export.xlsx')
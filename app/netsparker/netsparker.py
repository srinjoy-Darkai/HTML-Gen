from bs4 import BeautifulSoup
import os
import re
import openpyxl
import glob



class NETSPARKER:
    def __init__(self):
        self.vuls=[]

    def parse(self, files):
        for file in files:
            if not file.endswith('.html'): continue
            data=open(file, 'r', errors='ignore').read()
            soup=BeautifulSoup(data, 'lxml')
            vulns=soup.select_one('div.vuln-name').select('div.vuln-desc')
            for vuln in vulns:
                vul={'name':'', 'urls':[], 'risk_factor':'', 'cvss_score':'', 'cvss_vector':'', 'classifications':[], 'desc':'', 'impact':'', 'remedy':'', 'reference_links':[]}
                vul_header=vuln.select_one('div.vuln-desc-header')
                vul['name']=re.sub(r'\d+\.\s+', '', vul_header.select_one('h2').text)
                urls=vuln.next_sibling.select('.vuln-url')
                if urls==None: urls=vuln.next_sibling.next_sibling.select('.vuln-url')
                vul['urls']=list(map((lambda x: re.sub(r'[\d\.\s]+', '', x.find('div').text)), urls))
                vul['risk_factor']=re.sub(r'[\d\.\s]+', '', vul_header.select_one('.sev-box').text).title()
                
                vul['desc']='\n'.join(map((lambda x: x.text), vuln.find_all('p')))
                if vuln.select_one('h3'):
                    vul['impact']=vuln.select_one('h3').next_sibling.text
                
                vul_more_detail=vuln.next_sibling.next_sibling.select_one('.more-detail')
                if not vul_more_detail==None:
                    if vul_more_detail.find('h4', string='Remedy'):
                        vul['remedy']=vul_more_detail.find('h4', string='Remedy').next_sibling.text
                    vul['reference_links']=[]
                    for x in vul_more_detail.find_all('h4', string=['External References', 'Remedy References']):
                        for y in x.next_sibling.find_all('a'):vul['reference_links'].append(y.get('href'))
                    cvss_score=vul_more_detail.find_all(lambda tag: tag.name=='th' and 'CVSS' in tag.text)
                    if len(cvss_score):
                        vul['cvss_score']=float(re.sub(r'[^\d\.]+', '',cvss_score[-2].parent.parent.next_sibling.find_all('td')[1].text))
                        vul['cvss_vector']=cvss_score[-1].parent.parent.next_sibling.find('td').text
                
                if type(vul['cvss_score'])==type(1.0):
                    if vul['cvss_score']>8.9:vul['risk_factor']='Critical'
                    elif vul['cvss_score']>6.9:vul['risk_factor']='High'
                    elif vul['cvss_score']>3.9:vul['risk_factor']='Medium'
                    elif vul['cvss_score']>0:vul['risk_factor']='Low'
                    
                
                classifications=vuln.next_sibling.next_sibling.select_one('.classification-top')
                if not classifications==None:
                    classifications=classifications.find_all(lambda tag: tag.name=='td' and 'OWASP' in tag.text)
                    vul['classifications']=list(map(lambda x: x.text+' - '+x.next_sibling.text,classifications))
                self.vuls.append(vul)

    def createExcel(self):    
        severity_list=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'BESTPRACTICE', 'INFORMATION']
        self.vuls=sorted(self.vuls, key=lambda x: float(x['cvss_score']) if not x['cvss_score']=='' else 2, reverse=True)
        self.vuls=sorted(self.vuls, key=lambda x: severity_list.index(x['risk_factor'].upper()))


        wb_base=openpyxl.load_workbook('app/netsparker/base.xlsx')
        wb=wb_base.active
        i=1

        for vul in self.vuls:
            row=str(i+1)
            wb['A'+row]=i
            wb['B'+row]=vul['name']
            wb['C'+row]=', '.join(vul['urls'])
            wb['D'+row]=vul['risk_factor']
            wb['E'+row]=vul['cvss_score']
            wb['F'+row]=vul['cvss_vector']
            wb['G'+row]=', '.join(vul['classifications'])
            wb['H'+row]=vul['desc']
            wb['I'+row]=vul['impact']
            wb['J'+row]=vul['remedy']
            wb['K'+row]=', '.join(vul['reference_links'])
            i+=1

        wb_base.save('export.xlsx')
        os.startfile('export.xlsx')
    #     tempvulns.append(vul)



# with open('test.js', 'w', errors='ignore') as f: f.write('let data='+json.dumps(tempvulns))
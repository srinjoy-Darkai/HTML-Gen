from bs4 import BeautifulSoup
import glob
import openpyxl
import os
import re

class NETSPARKER:
    def __init__(self):
        self.vuls=[]
    
    def parseHTML(self, data):
        soup=BeautifulSoup(data, 'lxml')
        vulns=soup.select_one('div.vuln-name')
        vuln_descs=vulns.select('div.vuln-desc')
        vuln_vulns=vulns.select('div.vulns')
        vuln_more_detail=list(map(lambda x: x.next_sibling, vuln_vulns))
        
        for vul in enumerate(vuln_descs):
            vul_header=vul[1].select_one('div.vuln-desc-header')
            temp={'name':'', 'urls':[], 'risk_factor':'', 'cvss_score':'', 'cvss_vector':'', 'classifications':[], 'desc':'', 'impact':'', 'remedy':'', 'reference_links':[]}
            temp['name']=re.sub(r'\d+\.\s+', '', vul_header.select_one('h2').text)
            temp['urls']=list(map(lambda x: re.sub(r'(\d+\.)+\s+', '', x.find('div').text), vuln_vulns[vul[0]].select('.vuln-url')))
            temp['risk_factor']=re.sub(r'[\d\.\s]+', '', vul_header.select_one('.sev-box').text).title()
            if temp['risk_factor'].upper() in ['INFORMATION', 'BESTPRACTICE']:temp['risk_factor']="Informational"
            
            cvss_score=vuln_more_detail[vul[0]].find_all("thead", string=['CVSS 3.1 SCORE','CVSS 3.0 SCORE', 'CVSS 2.0 SCORE'])
            if len(cvss_score):
                temp['cvss_score']=re.sub(r'[^\d\.]+', '', cvss_score[-1].next_sibling.find('td', string="Base").next_sibling.text)
                temp['cvss_vector']=cvss_score[-1].parent.next_sibling.find('td').text
            
            cvss_classifications=vuln_more_detail[vul[0]].find_all('td', string=['OWASP 2013', 'OWASP 2017', 'CWE'])
            temp['classifications']=[x.text+'-'+x.next_sibling.text for x in cvss_classifications]
            
            temp['desc']='\n'.join(x.get_text() for x in vul[1].select('p'))
            temp['impact']=vul[1].select('div')[-1].get_text()
            try:
                temp['remedy']=vuln_more_detail[vul[0]].find('h4', string="Remedy").next_sibling.text
            except:pass
            try: 
                reference_links=vuln_more_detail[vul[0]].find_all('h4', string=["External References", "Remedy References"])
                for links in reference_links:temp['reference_links'].extend(list(map(lambda x: x['href'], links.next_sibling.select('a'))))
            except:pass
            self.vuls.append(temp)

    def sort(self):
        self.vuls=sorted(self.vuls, key=lambda x:x['cvss_score'], reverse=True)
        severities=['CRITICAL', 'HIGH', 'MEDIUM', "LOW", "INFORMATION", 'INFORMATIONAL', "BESTPRACTICE"]
        self.vuls=sorted(self.vuls, key=lambda x: severities.index(x['risk_factor'].upper()))


    def parse(self, files):
        for file in files:
            if os.path.isfile(file) and  file.endswith('.html'):
                file=open(file, 'r', errors='ignore').read()
                self.parseHTML(file)
                self.sort()
                
    def createExcel(self):
        base=openpyxl.load_workbook('app/netsparker/base.xlsx')
        wb=base.active
        for vul in enumerate(self.vuls):
            row=str(vul[0]+2)
            wb['A'+row]=row
            wb['B'+row]=vul[1]['name']
            wb['C'+row]=', '.join(vul[1]['urls'])
            wb['D'+row]=vul[1]['risk_factor']
            wb['E'+row]=vul[1]['cvss_score']
            wb['F'+row]=vul[1]['cvss_vector']
            wb['G'+row]=', '.join(vul[1]['classifications'])
            wb['H'+row]=vul[1]['desc']
            wb['I'+row]=vul[1]['impact']
            wb['J'+row]=vul[1]['remedy']
            wb['K'+row]=', '.join(vul[1]['reference_links'])
        base.save('export.xlsx')
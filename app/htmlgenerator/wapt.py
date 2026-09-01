from app.htmlgenerator.npt_assets import *
import openpyxl
import glob
import os
import json
import shutil


class waptHTMLGenerator:
    def __init__(self):
        self.componentwise={}
        self.netsparkerhosts={}
        self.vulwise={}
        self.nmaphosts={}
        self.totalCount={'CRITICAL':0, 'HIGH':0, 'MEDIUM':0, 'LOW':0, 'INFO':0, 'TOTAL':0}

    def netsparkerExcel(self, data):
        for row in data.iter_rows(min_row=2, values_only=True):
            if ',' in row[2]: hosts=row[2].split(',')
            elif ';' in row[2]: hosts=row[2].split(';')
            elif not row[2]: hosts=['*']
            else : hosts=[row[2]]

            self.vulwise[row[1]]={'name':row[1], 'cvss_score':row[4] if row[4] else '', 'risk_factor':row[3] if row[3] else '', 'cvss_vector':row[5] if row[5] else '', 'hosts':[x.strip() for x in hosts], 'cvss_classification':row[6] if row[6] else '', 'description':row[7], 'impact':row[8], 'remediation':row[9], 'referrence_links':[x.strip() for x in row[10].split(',')] if row[10] else []}
            temphosts=[]
            for host in hosts:
                if host in temphosts:continue
                if host not in self.netsparkerhosts: 
                    self.netsparkerhosts[host]={'address':host, 'vulnerabilities':[], 'open_ports':[]}
                    self.netsparkerhosts[host]['count']={'CRITICAL':0, 'HIGH':0, 'MEDIUM':0, 'LOW':0, 'INFO':-1, 'TOTAL':0}
                for risk in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                    if risk in row[3].upper():
                        self.netsparkerhosts[host]['count'][risk]+=1
                        self.netsparkerhosts[host]['count']['TOTAL']+=1
                        self.totalCount[risk]+=1
                        self.totalCount['TOTAL']+=1
                self.netsparkerhosts[host]['vulnerabilities'].append({'name':row[1], 'cvss_score':row[4] if row[4] else '', 'risk_factor':row[3] if row[3] else ''})
                temphosts.append(host)

    def parse(self):
        nessusfiles=glob.glob(input("Input Nessus Excel .xlsx Filename(s)/Wildcard: "))
        for file in nessusfiles:
            if os.path.isfile(file) and file.endswith('.xlsx'):
                self.netsparkerExcel(openpyxl.load_workbook(file).active)

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

    def componentwiseview(self):
        sl=1
        tempview=''
        for host in self.netsparkerhosts:
            host=self.netsparkerhosts[host]
            tempview+=VULTABLE_HOSTS.format(sl=sl, address=host['address'], critical=host['count']['CRITICAL'], high=host['count']['HIGH'], medium=host['count']['MEDIUM'], low=host['count']['LOW'], info=host['count']['INFO'], total=host['count']['TOTAL'])
            sl+=1
        total=VULTABLE_TOTAL_COUNTS.format(critical=self.totalCount['CRITICAL'], high=self.totalCount['HIGH'], medium=self.totalCount['MEDIUM'], low=self.totalCount['LOW'], info=self.totalCount['INFO'], total=self.totalCount['TOTAL'])
        return VULTABLE.format(hosts=tempview, totalCounts=total)

    def hostwisetable(self):
        returndata=''
        j=1
        for host in self.netsparkerhosts:
            host=self.netsparkerhosts[host]
            tempvularray=[]
            i=1
            returndata+='<br><h3 class="list-level-1" style="text-decoration:none;">1.{sl}. {address}</h3>'.format(address=host['address'], sl=j)
            j+=1
            if len(host['vulnerabilities'])>1:
                risk_factors={'CRITICAL':0, 'HIGH':0, 'MEDIUM':0, 'LOW':0, 'INFORMATIONAL':0, 'TOTAL':0}
                for vul in host['vulnerabilities']:
                    if risk_factors[vul['risk_factor'].upper()]<=0:
                        risk=HOST_VULTABLE_RISK_LEVEL.format(rowspan=host['count'][vul['risk_factor'].upper()], risk_factor=vul['risk_factor'])
                        risk_factors[vul['risk_factor'].upper()]+=1
                    else: risk=''
                    tempvularray.append(HOST_VULTABLE_VULS.format(sl=i, name=vul['name'], risk=risk, cvss_score=vul['cvss_score']))
                    i+=1
                vultable=HOST_VULTABLE.format(hosts=''.join(tempvularray))
            else: vultable=HOST_NO_VUL_FOUND
            returndata+=vultable
        return returndata

    def vulwisetable(self):
        returndata=''
        severities=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL', 'INFO']
        self.vulwise=sorted(self.vulwise.items(), key=lambda x: severities.index(x[1]['risk_factor'].upper()))
        i=1
        for vul in self.vulwise:
            if vul[1]['name']=='TEMP':continue
            returndata+=VULWISE_TABLE.format(risk_factor=vul[1]['risk_factor'], sl=i, name=vul[1]['name'], cvss_score=vul[1]['cvss_score'], cvss_vector=vul[1]['cvss_vector'], cvss_classification=vul[1]['cvss_classification'], hosts=','.join(vul[1]['hosts']), description=vul[1]['description'].replace('<', '&lt;').replace('>', '&gt;') if vul[1]['description'] else '', impact=vul[1]['impact'].replace('<', '&lt;').replace('>', '&gt;') if vul[1]['impact'] else '', remediation=vul[1]['remediation'].replace('<', '&lt;').replace('>', '&gt;') if vul[1]['remediation'] else '', reference_links="<b>Reference Link:</b><br>"+'<br>'.join(map(lambda x: '<a style="font-size: 9pt" href="{link}">{link}</a>'.format(link=x), vul[1]['referrence_links'])) if len(vul[1]['referrence_links'])>0 else '')
            i+=1
        return returndata



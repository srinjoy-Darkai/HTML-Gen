import re

file = open('nmap.txt', 'r', errors='ignore').read()

file=file.split('Host No.')
file.pop(0)

for host in file:
    services=re.findall(r'(\d+)\/(tcp|udp)(?:\t+|\s+)(?:open)?(?:\t+|\s+)?(\S+)(.*)?', host)
    ip=re.findall(r'IP\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})', host)
    print(ip)
    if len(services):
        print(services)
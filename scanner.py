#!/usr/bin/python3.10
import sys
import time
import ipaddress
import logging

from scanner_host import scan_arp, scan_icmp
from scanner_protocol import scan_syn, scan_udp, set_protocole_name

logging.getLogger('scapy.runtime').setLevel(logging.ERROR)

if len(sys.argv) == 1:
    exit('Entrer la cible avec le type de scan'
         'ex: ./scanner.py 192.168.0.10/24 OU'
         './scanner.py ICMP 192.168.0.10')

target = sys.argv[1]
start = time.time()
range_ = None
cmpt_r = 0
set_protocole_name()  # NOTE met en place les numero des port tcp udp


def start_scan(type_scan: str, target: str, ports: bool = False):
    match type_scan:
        case 'icmp': scan_icmp(target)
        case 'arp':  scan_arp(target)
        case 'syn':  scan_syn(target, ports)
        case 'udp':  scan_udp(target, ports)


if len(sys.argv) == 2:
    if '/' in target:
        if '-' in target: #NOTE range ip
            range_ = target.split('-')[1].split('/')[0]
            target = target.split('-')[0] + '/' + target.split('/')[1]
            
        for ip in ipaddress.ip_network(target, False).hosts():
            if range_ and  range_ == (cmpt_r - 1):
                break 
            
            ip = str(ip)

            scan_icmp(ip)
            scan_arp(ip)

            scan_syn(ip, False)
            scan_udp(ip, False)
    else:
        scan_icmp(target)
        scan_arp(target)

        scan_syn(target, False)
        scan_udp(target, False)

elif len(sys.argv) > 2:
    for arg in sys.argv[1::]:
        arg = arg.lower()
        if '/' in target:
            for ip in ipaddress.ip_network(target, False).hosts():
                ip = str(ip)
                start_scan(ip, False)

        else:
            start_scan(target, False) # NOTE j'ai laisser expres, pour me rappeller qu'il faut l'implimentais


print(time.time() - start)

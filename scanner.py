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

TARGET = sys.argv[1]
start = time.time()

set_protocole_name()  # NOTE met en place les numero des port tcp udp


def start_scan(type_scan: str, target: str):
    match type_scan:
        case 'icmp': scan_icmp(target)
        case 'arp':  scan_arp(target)
        case 'syn':  scan_syn(target, False)
        case 'udp':  scan_udp(target, False)


if len(sys.argv) == 2:
    if '/' in TARGET:
        for ip in ipaddress.ip_network(TARGET, False).hosts():
            ip = str(ip)

            scan_icmp(ip)
            scan_arp(ip)

            scan_syn(ip, False)
            scan_udp(ip, False)
    else:
        scan_icmp(TARGET)
        scan_arp(TARGET)

        scan_syn(TARGET, False)
        scan_udp(TARGET, False)

elif len(sys.argv) > 2:
    for arg in sys.argv[1::]:
        arg = arg.lower()
        if '/' in TARGET:
            for ip in ipaddress.ip_network(TARGET, False).hosts():
                ip = str(ip)
                start_scan(ip)
                match arg:
                    case 'icmp': scan_icmp(ip)
                    case 'arp':  scan_arp(ip)
                    case 'syn':  scan_syn(ip, False)
                    case 'udp':  scan_udp(ip, False)

        else:
            start_scan(TARGET)


print(time.time() - start)

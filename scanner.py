#!/usr/local/bin/python3.10
import sys 
import time 
import ipaddress
import logging

from  scanner_host import scan_arp, scan_icmp
from  scanner_protocol import get_protocole_name, ScanTCP, ScanUDP

logging.getLogger('scapy.runtime').setLevel(logging.ERROR)

if len(sys.argv) == 1: 
        exit('Entrer la cible avec le type de scan'
                'ex: ./scanner.py 192.168.0.10/24 OU'
                './scanner.py ICMP 192.168.0.10')

TARGET = sys.argv[-1]
start = time.time()

# recuperer les port tcp, udp est leur nom
tcp_ports, udp_ports, names_port = get_protocole_name()

        
tcp_scan = ScanTCP(tcp_port=tcp_ports)
udp_scan = ScanUDP(udp_port=udp_ports)

if len(sys.argv) == 2:
    if '/' in TARGET: 
        for ip in  ipaddress.ip_network(TARGET, False).hosts(): 
            ip = str(ip)

            scan_icmp(ip)
            scan_arp(ip)

            tcp_scan.SYN(ip)
            udp_scan.run(ip)
            print()
    else: 
        scan_icmp(TARGET)
        scan_arp(TARGET)

        tcp_scan.SYN(TARGET)
        udp_scan.run(TARGET)

elif len(sys.argv) > 2: 
    for arg in sys.argv[1::]:
        arg = arg.lower()
        if '/' in TARGET:
            for ip in  ipaddress.ip_network(TARGET, False).hosts(): 
                ip = str(ip)
                match arg:        
                    case 'icmp' : scan_icmp(ip)
                    case 'arp' :  scan_arp(ip)
                    case 'syn' :  tcp_scan.SYN(ip)
                    case 'udp' :  udp_scan.run(ip)
    
        else: 
            match arg: 
                case 'icmp' : scan_icmp(TARGET) 
                case 'arp' :  scan_arp(TARGET)
                case 'syn' :  tcp_scan.SYN(TARGET)
                case 'udp' :  udp_scan.run(TARGET)


print(time.time() - start)



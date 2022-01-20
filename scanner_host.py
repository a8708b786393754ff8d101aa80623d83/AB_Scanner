#!/usr/local/bin/python3.10
from scapy.all import Ether, IP, srp, ARP, ICMP

def scan_icmp(target: str):
    pkt = Ether() / IP(dst=target) / ICMP()
    ans, _ = srp(pkt, timeout=1, verbose=0) 
    # envoie du packet avec la methode srp pour avoir l'adresses mac
    
    for element in ans:
        if element[1]['ICMP'].type == 0: 
            mac_target = element[1]['Ethernet'].src
            print(target,'--->',mac_target,' ::ICMP')

def scan_arp(target: str): 
    pkt = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=target)
    ans, _ = srp(pkt, verbose=0, timeout=1)

    for element in ans:
        mac_target = element[1]["Ethernet"].src
        print(target,'--->',mac_target,' ::ARP')

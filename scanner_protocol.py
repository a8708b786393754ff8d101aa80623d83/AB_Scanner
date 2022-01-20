#!/usr/local/bin/python3.10
import json
import requests

from scapy.all import TCP, IP, UDP, ICMP, sr

def get_protocole_name():
    ports_tcp = []
    ports_udp = []
    name = []

    with open('port_protocol.json', 'r') as j_port:
        data = json.load(j_port)

    for i, element in enumerate(data.items()):
        if i != 0:
            if element[0].endswith('/tcp'):
                port = element[0].split('/')
                ports_tcp.append(int(port[0]))

            if element[0].endswith('/udp'):
                port = element[0].split('/')
                ports_udp.append(int(port[0]))

            name.append(element[1]['name'])
    return [ports_tcp, ports_udp, name]


class ScanPORT:
    def __init__(self, tcp_port: list = None, udp_port: list = None, all_port=False):
        self.tcp = tcp_port
        self.udp = udp_port
        self.all_port = all_port

    def state(self, ans, port: int):
        for element in ans:
            target = element[1]['IP'].src

            if element[1].haslayer(TCP):  # partie pour les packet SYN
                if element[1]['TCP'].flags == 'SA':
                    print(target, '--->', port, '::SYN')

                    if port in [80, 443, 8080, 8000]:
                        self.get_headers(element[1]['IP'].src, port)

            # partie pour les packet UDP OU le scan tcp noel (je verifie le protocle icmp)
            elif element[1].haslayer(ICMP):
                if element[1]['ICMP'].type == 3 and element[1]['ICMP'].code in [1, 2, 9, 10, 13]:
                    print(target, '--->', port, '::SYN')

            # pour voir si le packet continet une trame udp
            elif element[1].haslayer(UDP):
                port_udp_open = element[1]['UDP'].dport
                print(target, '--->', port_udp_open, '::UDP')

    def get_headers(self, target: str, port: int):
        try:
            if port == 443:
                resp = requests.get(f'https://{target}/')
            else:
                resp = requests.get(f'http://{target}/')
        except:
            return None

        if resp.ok:
            print("*******************************")
            for keys, values in resp.headers.items():
                print(keys, ' : ', values)
            print("*******************************")

            return None

        print('Il n ya pas de service web executer sur ce port')


class ScanTCP(ScanPORT):
    def SYN(self, target: str):
        pkt = IP(dst=target) / TCP(flags='S', sport=1234)

        for port in self.tcp:
            port = int(port)
            if self.all_port != True:
                if port < 1023:
                    pkt['TCP'].dport = port
                    ans, _ = sr(pkt, verbose=0, timeout=1)
                    self.state(ans, port)

            else:
                pkt['TCP'].dport = port
                ans, _ = sr(pkt, verbose=0, timeout=1)
                self.state(ans, port)

    # pas besoin de faire un scan ack, ce type de scan c'est pour savoir si le port est filtrer ou non
    def ACK(self, target: str): pass


class ScanUDP(ScanPORT):
    def run(self, target: str):
        pkt = IP(dst=target) / UDP(sport=1234)

        for port in self.udp:
            port = int(port)
            if self.all_port != True:
                if port < 1023:
                    pkt['UDP'].dport = port
                    ans, _ = sr(pkt, verbose=0, timeout=1)
                    self.state(ans, port)

            else:
                pkt['UDP'].dport = port
                ans, _ = sr(pkt, verbose=0, timeout=1)
                self.state(ans, port)

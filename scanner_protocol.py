import json
import requests

from scapy.layers.inet import TCP, IP, UDP, ICMP
from scapy.sendrecv import sr

ports_tcp = []
ports_udp = []
name_port = []


def set_protocole_name():
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

            name_port.append(element[1]['name'])


def state(ans, port: int):
    for element in ans:
        target = element[1][IP].src

        if element[1].haslayer(TCP):  # NOTE partie pour les packet SYN
            if element[1][TCP].flags == 'SA':
                print(target, '--->', port, '::SYN', port)

                if port in [80, 443, 8080, 8000]:
                    get_headers(element[1][IP].src, port)

        # NOTE partie pour les packet UDP OU le scan tcp noel (je verifie le protocle icmp)
        elif element[1].haslayer(ICMP):
            if element[1][ICMP].type == 3 and element[1][ICMP].code in [1, 2, 9, 10, 13]:
                print(target, '--->', port, '::SYN')

        # NOTE pour voir si le packet continet une trame udp
        elif element[1].haslayer(UDP):
            port_udp_open = element[1]['UDP'].dport
            print(target, '--->', port_udp_open, '::UDP')


def get_headers(target: str, port: int):
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


def scan_syn(target: str, all_port: bool = True):
    pkt = IP(dst=target) / TCP(flags='S', sport=1234)

    for port in ports_tcp:
        port = int(port)

        if  not all_port and port > 1023:
            return None 
            
        pkt[TCP].dport = port
        ans, _ = sr(pkt, verbose=0, timeout=2)
        state(ans, port)


def scan_udp(target: str, all_port: bool = True):
    pkt = IP(dst=target) / UDP(sport=1234)

    for port in ports_udp:
        port = int(port)

        if not all_port and port > 1023:
            return None 

        pkt[UDP].dport = port
        ans, _ = sr(pkt, verbose=0, timeout=2)
        state(ans, port)

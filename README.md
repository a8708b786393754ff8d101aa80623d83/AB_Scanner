# ABScanner 
## Python script that looks for open ports/targets

## Using
You must specify a target or a network with the subnet mask
### Type of scans: 
```
SYN, ICMP, UDP and ARP
```
If you just put the target, the scanner script with all  types of scans:
```sh
./scanner.py 192.168.0.10
./scanner.py 192.168.0.10/24
```
To choose a type of scan, you have to specify it (it doesn't care about the case);
```sh
./scanner.py  192.168.0.10 SYN 
./scanner.py  192.168.0.10/24 ICMP
./scanner.py  10.10.10.10/16 ARP
./scanner.py  192.168.0.254 UDP
```
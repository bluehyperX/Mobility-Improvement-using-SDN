#!/usr/bin/python
from scapy.all import *
import os
import json
# import time

def pkt_callback(pkt):
    # if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 8:
    #     print("Beacon")
    # if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 0:
    #     print("Association Request")
    # if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 10:
    #     print("Disassociation")
    # if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 12:
    #     print("Disauthentication")

    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 1:
        print("Association Response")
        
        f = open('/home/wifi/ACN/Project/alert.txt', 'w+')
        f.write("1")
        f.close()
        # msg = "subtype: %s" % (pkt.subtype) #subtype: 1
        # packet = Ether()/IP(src="10.0.0.3", dst="10.0.0.1")/TCP(sport=8000, dport=6653)/msg
        # send(packet, verbose=0)

# time.sleep(50)
sniff(iface="hwsim0", prn=pkt_callback)
#!/usr/bin/python
from scapy.all import *
import os
# import time
# os.popen("gnome-terminal")

def pkt_callback(pkt):
    # if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 8:
    #     print("Beacon")
    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 0:
        print("Association Request")
        msg = "%d" % (pkt.subtype) #subtype: 0
        packet = Ether()/IP(src="10.0.0.4", dst="10.0.0.100")/TCP(sport=8000, dport=6653)/msg
        send(packet, verbose=0)

    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 10:
        print("Disassociation")
        msg = "%d" % (pkt.subtype) #subtype: 10
        packet = Ether()/IP(src="10.0.0.4", dst="10.0.0.100")/TCP(sport=8000, dport=6653)/msg
        send(packet, verbose=0)

    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 12:
        print("Disauthentication")
        msg = "%d" % (pkt.subtype) #subtype: 12
        packet = Ether()/IP(src="10.0.0.4", dst="10.0.0.100")/TCP(sport=8000, dport=6653)/msg
        send(packet, verbose=0)

    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 1:
        print("Association Response")
        msg = "%d" % (pkt.subtype) #subtype: 1
        packet = Ether()/IP(src="10.0.0.4", dst="10.0.0.100")/TCP(sport=8000, dport=6653)/msg
        send(packet, verbose=0)
        
        # f = open('/home/wifi/ACN/Project/alert.txt', 'w+')
        # f.write("1")
        # f.close()

# time.sleep(50)
# sniff(iface="hwsim0", prn=pkt_callback)
sniff(iface="mon0", prn=pkt_callback)
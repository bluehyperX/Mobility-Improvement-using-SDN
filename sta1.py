#!/usr/bin/python
from scapy.all import *
import os
# import time
# os.popen("gnome-terminal")

def pkt_callback(pkt):
    # if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 8:
    #     print("Beacon")
    # if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 0:
    #     print("Association Request")
    #     # msg = "%d" % (pkt.subtype) #subtype: 0
    #     # packet = Ether()/IP(src="10.0.0.7", dst="127.0.0.1")/TCP(sport=8000, dport=6653)/"Association Request"
    #     packet = Ether()/IP(dst="127.0.0.1")/UDP(sport=8000, dport=6653)/"Association Request"
    #     sendp(packet, iface="con-eth0", verbose=0)

    # if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 10:
    #     print("Disassociation")
    #     # msg = "%d" % (pkt.subtype) #subtype: 10
    #     # packet = Ether()/IP(src="10.0.0.7", dst="127.0.0.1")/TCP(sport=8000, dport=6653)/"Disassociation"
    #     packet = Ether()/IP(dst="127.0.0.1")/UDP(sport=8000, dport=6653)/"Disassociation"
    #     sendp(packet, iface="con-eth0", verbose=0)

    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 12:
        print("Disconnect")
        # msg = "%d" % (pkt.subtype) #subtype: 12
        # packet = Ether()/IP(src="10.0.0.7", dst="127.0.0.1")/TCP(sport=8000, dport=6653)/"Disauthentication"
        payload_data = b'Disconnect'
        packet = Ether()/IP(dst="127.0.0.1")/UDP(sport=8000, dport=6653)/Raw(load=payload_data)
        sendp(packet, iface="s1-eth1", verbose=0)

    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 1:
        print("Connect")
        # msg = "%d" % (pkt.subtype) #subtype: 1
        # packet = Ether()/IP(src="10.0.0.7", dst="127.0.0.1")/TCP(sport=8000, dport=6653)/"Association Response"
        payload_data = b'Connect'
        packet = Ether()/IP(dst="127.0.0.1")/UDP(sport=8000, dport=6653)/Raw(load=payload_data)
        sendp(packet, iface="s1-eth1", verbose=0)
        
        # f = open('/home/wifi/ACN/Project/alert.txt', 'w+')
        # f.write("1")
        # f.close()

# time.sleep(50)
sniff(iface="hwsim0", prn=pkt_callback)
# sniff(iface="mon0", prn=pkt_callback)
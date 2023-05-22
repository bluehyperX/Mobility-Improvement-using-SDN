#!/usr/bin/python
from scapy.all import *

def pkt_callback(pkt):

    #This send the packets to interfaces which are connected to the corresponding APs'. Then from those AP's these packets are sent to the controller 
    #via packet-in. Now controller has the datapath of the AP's and can send add or delete flowmods to the APs
    m ={"00:00:00:00:00:01":"s4-eth2","00:00:00:00:00:02":"s3-eth4","00:00:00:00:00:03":"s5-eth2"}   

    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 12:
        print('Disconnected! Sender MAC address: ', pkt[Dot11].addr2, ', Port: ', m[(pkt[Dot11].addr1)], ', Destination MAC address: ', pkt[Dot11].addr1)
        payload_data = b'Disconnect'
        packet = Ether(src=pkt[Dot11].addr2, dst=pkt[Dot11].addr1)/IP(src="10.0.0.7", dst="127.0.0.1")/UDP(sport=8000, dport=6653)/Raw(load=payload_data)
        sendp(packet, iface=m[(pkt[Dot11].addr1)], verbose=0)

    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 1:
        print('Connected! Sender MAC address: ', pkt[Dot11].addr2, ', Port: ', m[(pkt[Dot11].addr2)], ', Destination MAC address: ', pkt[Dot11].addr1)
        payload_data = b'Connect'
        packet = Ether(src=pkt[Dot11].addr1, dst=pkt[Dot11].addr2)/IP(src="10.0.0.7", dst="127.0.0.1")/UDP(sport=8001, dport=6653)/Raw(load=payload_data)
        sendp(packet, iface=m[pkt[Dot11].addr2], verbose=0)

sniff(iface="hwsim0", prn=pkt_callback)
# sniff(iface="mon0", prn=pkt_callback)
import os
import socket
import ssl
import threading
from scapy.all import *
from scapy.layers.l2 import Ether
import tunnel
#define 

class MyTapWindows():

    def read():
        return pkt_list.pop()

    def write(data):
        sendp(bytes(data), iface=self.tap_interface, verbose=False)

    def init():

        def pkt_test(pkt, mac):
            return pkt[Ether].src == mac

        def pkt_send(pkt, pkt_list, pkts_rcvd):
            pkt_list.append(pkt)
            pkts_rcvd[0] = pkts_rcvd[0]+1

        pkt_list = []
        sniffing = threading.Thread(target=sniff, args=(iface=self.tap_interface, lfilter = lambda y: pkt_test(y, Ether().src), prn = lambda x:pkt_send(x,pkt_list,self.pkts_rcvd))

        




       
        
        



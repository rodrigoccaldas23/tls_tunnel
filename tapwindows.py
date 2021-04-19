import os
import socket
import ssl
import threading
from scapy.all import *
from scapy.layers.l2 import Ether
import time

class MyTapWindows():
    
    
    def read(self):
        while True:
            #read bloqueante
            if len(pkt_list) < 1:
                raise OSError(errno.EWOULDBLOCK, os.strerror(errno.EWOULDBLOCK))
            else:
                break
        return bytes(pkt_list.pop())

    def write(self,data):
        tap_interface = 'tap0'
        sendp(bytes(data), iface=tap_interface, verbose=False)

    def init(self, pkt_x):
        
        global pkt_list
        pkt_list = []

        def pkt_test(pkt, mac):
            return pkt[Ether].src == mac

        def pkt_send(pkt, pkt_list, pkts_rcvd):
            pkt_list.append(pkt)
            pkts_rcvd[0] = pkts_rcvd[0]+1

        def ThreadTapFunction(tap_interface,pkt_list,mac_add,pkts_rcvd):
            sniff(iface=tap_interface, lfilter = lambda y: pkt_test(y, mac_add), prn = lambda x:pkt_send(x,pkt_list,pkts_rcvd))
            
        tap_mac_address = '00:ff:8d:21:b0:c5'
        tap_interface = 'tap0'
        pkts_rcvd = pkt_x

        th = threading.Thread(target=ThreadTapFunction, args=(tap_interface,pkt_list,tap_mac_address,pkts_rcvd,))

        th.daemon = True
        th.start()

        




       
        
        



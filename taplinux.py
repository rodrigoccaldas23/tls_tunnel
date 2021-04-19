import socket
from socket import AF_INET, SOCK_STREAM, SO_REUSEADDR, SOL_SOCKET, SHUT_RDWR
import ssl

import threading
#import tunnel
from pytun import TunTapDevice, IFF_TAP, IFF_NO_PI

import errno
import fcntl
import os
import select

from time import sleep

import token_bucket


class MyTapLinux():

    def read(self):
        return self.tap.read(self.tap.mtu + 20)

    def write(self, data):
        print("write na taplinux")
        self.tap.write(data)
        print("write na taplinux")

    def init(self, tap_interface, tap_mtu):
        # Initialize a TAP interface and make it non-blocking
        self.tap_interface = tap_interface
        self.tap = TunTapDevice(
            flags=IFF_TAP | IFF_NO_PI, name=self.tap_interface)
        self.tap.up()
        fcntl.fcntl(self.tap.fileno(), fcntl.F_SETFL, os.O_NONBLOCK)
        self.tap.mtu = tap_mtu
        # return self.tap

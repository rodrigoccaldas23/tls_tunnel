import socket
from socket import AF_INET, SOCK_STREAM, SO_REUSEADDR, SOL_SOCKET, SHUT_RDWR
import ssl

import threading
import tunnel
from pytun import TunTapDevice, IFF_TAP, IFF_NO_PI

import errno
import fcntl, os
import select

from time import sleep

import token_bucket


class MyTapLinux():

    def read():
        return tap.read(tap.mtu + 20)

    def write(data):
        self.tap.write(data)

    def init():
        # Initialize a TAP interface and make it non-blocking
		self.tap = TunTapDevice(flags = IFF_TAP|IFF_NO_PI, name=self.tap_interface); self.tap.up()
		fcntl.fcntl(self.tap.fileno(), fcntl.F_SETFL, os.O_NONBLOCK)
		self.tap.mtu = self.tap_mtu
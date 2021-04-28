#!/usr/bin/env python
import socket
import ssl
import threading
import psutil
import ipaddress
import errno
import os
import select
from time import sleep
import secrets
import argparse

from random import randint

# Main thread receives user input, a server thread waits for new
# connections and serves them, TAP thread reads the interface and
# sends the packets to every open connection.

# The server thread calls a new thread for each client to deal with
# the TCP connection, reading received packets and putting them on
# the TAP interface.


def r(c):
    print(c)
    os.system(c)


def resolve_hostname(name, tries=5):
    addr = None
    while addr == None and tries > 0:
        try:
            addr = socket.gethostbyname_ex(name)[2][0]
        except:
            r('sleep 2s')
            tries = tries - 1
    return addr


def shouldSendFakePacket():
    return (randint(0, 1) == 1)


def fakePacket():
    length = randint(65, 73)
    return b'\x00' + secrets.token_bytes(length) + b'\x00'


class TLSTunnel():

    def initialize(self):

        # parse arguments
        parser = argparse.ArgumentParser(description='TLS tunnel client')
        parser.add_argument('--mode', dest='mode', type=str, default="server")
        parser.add_argument(
            '--priv_net_addr', dest='priv_net_addr', type=str, default='192.168.1.3')
        parser.add_argument('--tap_mtu', dest='tap_mtu',
                            type=int, default=1500)
        parser.add_argument('--system', dest='system',
                            type=str, default="linux")
        parser.add_argument('--padding', dest='padding',
                            type=str, default="no")
        parser.add_argument('--fakepackets', dest='fakepackets',
                            type=str, default="no")
        # server
        parser.add_argument(
            '--listen_addr', dest='listen_addr', default='10.1.2.1')
        parser.add_argument(
            '--listen_port', dest='listen_port', type=int, default=8082)
        parser.add_argument('--tb_rate', dest='tb_rate', type=int, default=100)
        parser.add_argument('--tb_burst', dest='tb_burst',
                            type=int, default=1000)
        # client
        parser.add_argument(
            '--server_addr', dest='server_addr', default='10.1.2.1')
        parser.add_argument(
            '--server_port', dest='server_port', type=int, default=8082)
        parser.add_argument('--server_sni_hostname',
                            dest='server_sni_hostname', default='safecities')
        self.args = parser.parse_args()

        self.tap_mtu = self.args.tap_mtu
        if self.args.mode == 'client':
            print("**Client**")
            self.server_port = self.args.server_port
            self.server_sni_hostname = self.args.server_sni_hostname

            self.server_cert = 'server.crt'
            self.client_cert = 'client.crt'
            self.client_key = 'client.key'

            self.pkts_rcvd = [0]
            self.pkts_sent = 0
        elif self.args.mode == 'server':
            print("**Server**")
            self.server_cert = 'certs/server.crt'
            self.server_key = 'certs/server.key'
            self.client_certs_path = 'certs/'

            self.tb_rate = self.args.tb_rate
            self.tb_burst = self.args.tb_burst

            self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.context.verify_mode = ssl.CERT_REQUIRED
            self.context.load_cert_chain(
                certfile=self.server_cert, keyfile=self.server_key)
            self.context.load_verify_locations(capath=self.client_certs_path)

            # List of active connections - dicts, with IP, port, socket object,
            # thread signal (to kill corresponding thread), and Common Name
            # example_connection = {
            #	'ip' : '10.0.0.2',
            #	'port' : 2000,
            #	'socket' : conn,
            #	'kill_signal' : False,
            #	'CN' : 'client'
            # }
            self.active_connections = []
        else:
            print("Unnown mode -- choose between client and server")

        # linux or windows tap
        if self.args.system == 'linux':
            from taplinux import MyTapLinux
            from socket import gethostbyname_ex, AF_INET, SOCK_STREAM, SO_REUSEADDR, SOL_SOCKET, SHUT_RDWR
            from pytun import TunTapDevice, IFF_TAP, IFF_NO_PI
            self.tap = MyTapLinux()
        else:
            from tapwindows import MyTapWindows
            self.tap = MyTapWindows()

        if self.args.padding == 'no':
            self.padding = 0
        else:
            self.padding = 1

        if self.args.fakepackets == 'no':
            self.fakepackets = 0
        else:
            self.fakepackets = 1

    def create_tap(self):

        # identify interface for bridging, will may take some time to be created

        def get_interface_for_ip(addr):
            mon_if_name = ''
            addrs = psutil.net_if_addrs()
            for netif in addrs:
                for iface in addrs[netif]:
                    # print (str(iface.family))
                    if str(iface.family) == 'AddressFamily.AF_INET':
                        ip_addr = ipaddress.IPv4Network(
                            (addrs[netif][0].address, addrs[netif][0].netmask), strict=False)
                        print(ip_addr.network_address)
                        if self.args.priv_net_addr.split('/')[0] == str(addrs[netif][0].address):
                            mon_if_name = netif
                            break
            return mon_if_name

        mon_if_name = get_interface_for_ip(self.args.priv_net_addr)

        while mon_if_name == '' or mon_if_name is None:
            print("waiting for interface to be active " + self.args.priv_net_addr)
            r("/bin/sleep 2s")
            mon_if_name = get_interface_for_ip(self.args.priv_net_addr)

        # create tap
        self.tap_interface = 'tap0'

        addrs = psutil.net_if_addrs()
        if mon_if_name == '':
            print('No interface specified')
        elif self.tap_interface not in addrs:
            print('Creating tap ' + self.tap_interface + ' for ' + mon_if_name)
            # os.system("/root/environments/tls/start-tap.sh " + mon_if_name + " 10.0.2.2/24")
            r("mkdir /dev/net")
            r("mknod /dev/net/tun c 10 200")
            r("ip tuntap add tap0 mode tap")
            r("brctl addbr br0")
            r("ip link set tap0 up")
            r("ip link set br0 up")
            r("brctl addif br0 tap0")
            r("brctl addif br0 " + mon_if_name)
            r("ip addr del " + self.args.priv_net_addr + " dev " + mon_if_name)
            r("ip addr add " + self.args.priv_net_addr + " dev br0")
        else:
            print('Tap already created')

        # Initialize a TAP interface and make it non-blocking
        self.tap.init(self.tap_interface, self.tap_mtu)

    def srvThreadTapReadFunction(self, tap, conn_list):
        # Check for packets in tap interface and send them to every active connection
        # version1.2
        print("Tap thread started")
        while True:
            try:
                packet = tap.read()
                buf = self.packet_to_bytes(packet, self.padding)

            except Exception as e:
                if e.args[0] == errno.EAGAIN or e.args[0] == errno.EWOULDBLOCK:
                    # If we wish to insert a "fake packet", fill 'buf'
                    # if there is no real packet, do we want a fake packet?
                    if shouldSendFakePacket() and self.fakepackets == 1:
                        fake_packet = fakePacket()
                        buf = self.packet_to_bytes(
                            fake_packet, self.padding, fake_packet=True)
                    else:
                        # we don't want to send a fake packet, and we don't have real packet
                        # wait a bit and try to read the tap again:
                        sleep(0.1)
                        continue
                else:
                    print(e)
                    raise

            for conn in conn_list:
                if conn['kill_signal'] == False:
                    try:
                        conn['socket'].send(buf)
                    except OSError as exc:
                        print("Error while sending data to {}:{} ({})".format(
                            conn['ip'], conn['port'], conn['CN']))
                        if exc.errno == errno.EPIPE:
                            print("Broken pipe. Sending kill signal...")
                            conn['kill_signal'] = True

    # per client read from ssl and write into tap

    def srvThreadTapWrite(self, clientsocket, addr, clienttap, conn_list, buckets):
        print("New TCP Connection: {}:{}".format(addr[0], addr[1]))
        try:
            conn = self.context.wrap_socket(clientsocket, server_side=True)
        except Exception as e:
            print("SSL connection not established.")
            print(e)
            print("")
            return

        print("SSL established.")
        print("Peer: {}".format(conn.getpeercert()))

        new_conn = {
            'ip': addr[0],
            'port': addr[1],
            'socket': conn,
            'kill_signal': False,
            'CN': [cn for ((n, cn),) in conn.getpeercert()['subject'] if n == 'commonName'][0]
        }

        conn_list.append(new_conn)
        conn.setblocking(0)
        while new_conn['kill_signal'] == False:
            try:
                # timestamp and add tokens to bucket
                ready = select.select([conn], [], [], 0.1)
                if ready[0]:
                    data = self.get_packet_from_tls(conn)
                    # data = conn.recv(clienttap.mtu)
                    if data:
                        if buckets.consume(new_conn['CN']):
                            # print("tb OK", new_conn['CN'], buckets._storage.get_token_count(new_conn['CN']))
                            # Remove padding or fake packets. First bytes 2 dictate real size.
                            # Also, apply a firewall here! (decide if a packet coming
                            # from the TLS tunnel should go to the network interface)
                            clienttap.write(data)
                        else:
                            # print("tb XX", new_conn['CN'], buckets._storage.get_token_count(new_conn['CN']))
                            pass

                    else:
                        sleep(0.05)
            except OSError as exc:
                if exc.errno == errno.ENOTCONN:
                    print(
                        "Connection to {} closed by remote host.".format(addr[0]))
                    break
        conn_list.remove(new_conn)

        try:
            conn.shutdown(socket.SHUT_RDWR)
            conn.close()
            print("Connection to {}:{} ({}) closed.".format(
                new_conn['ip'], new_conn['port'], new_conn['CN']))
        except:
            pass

    def srvThreadServerFunction(self, listen_addr, listen_port, conn_list, buckets):
        bindsocket = socket.socket()
        bindsocket.bind((listen_addr, listen_port))
        bindsocket.listen(5)

        print("Waiting for clients")
        # Wait for new connections and serve them, creating a thread for each client
        while True:
            newsocket, fromaddr = bindsocket.accept()  # blocking call
            client_thread = threading.Thread(target=self.srvThreadTapWrite, args=(
                newsocket, fromaddr, self.tap, conn_list, buckets,))
            client_thread.daemon = True
            client_thread.start()

    def srvThreadCLI(clientsocket, addr, clienttap, conn_list):
        print("Available commands: close, block, list, exit")
        while True:
            try:
                inp = input('>> ')
                if inp == "close":
                    print("\nActive connections:")
                    for i, connection in enumerate(active_connections):
                        print("{} - {}:{} ({})".format(i,
                                                       connection['ip'], connection['port'], connection['CN']))

                    chosen_connection = input(
                        "Which connection to close? [0-{}] >> ".format(len(active_connections)-1))
                    try:
                        c = active_connections[int(chosen_connection)]
                    except:
                        pass
                    else:
                        confirmation = input(
                            "Terminate connection to {}:{} ({})? (Y/n) >> ".format(c['ip'], c['port'], c['CN']))
                        if confirmation != "N" and confirmation != "n":
                            c['kill_signal'] = True
                            print("Kill signal sent.")

                elif inp == "block":
                    print("\nActive clients:")
                    cn_list = list(set([conn['CN']
                                        for conn in active_connections]))
                    for i, client in enumerate(cn_list):
                        print("{} - {}".format(i, client))

                    chosen_connection = input(
                        "Which certificate to block? [0-{}] >> ".format(len(cn_list)-1))
                    try:
                        chosen_cn = cn_list[int(chosen_connection)]
                    except:
                        pass
                    else:
                        confirmation = input(
                            "Terminate every connection from client [{}]? (Y/n) >> ".format(chosen_cn))
                        if confirmation != "N" and confirmation != "n":
                            for conn in active_connections:
                                if conn['CN'] == chosen_cn:
                                    conn['kill_signal'] = True
                                    print("Kill signal sent to {}:{}.".format(
                                        conn['ip'], conn['port']))

                elif inp == "list":
                    print("\nActive connections:")
                    for i, connection in enumerate(active_connections):
                        print("{} - {}:{} ({})".format(i,
                                                       connection['ip'], connection['port'], connection['CN']))
                    print("\nActive clients:")
                    cn_list = list(set([conn['CN']
                                        for conn in active_connections]))
                    for i, client in enumerate(cn_list):
                        print("{} - {}".format(i, client))

                elif inp == "update":
                    context = ssl.create_default_context(
                        ssl.Purpose.CLIENT_AUTH)
                    context.verify_mode = ssl.CERT_REQUIRED
                    context.load_cert_chain(
                        certfile=server_cert, keyfile=server_key)
                    context.load_verify_locations(capath=client_certs_path)
                    print("Updating client certificates...")

                elif inp == "exit":
                    print("Terminating server. Closing connections...")
                    for connection in active_connections:
                        connection['kill_signal'] = True
                    sleep(3)
                    break

            except KeyboardInterrupt as e:
                print("\nKeyboard interrupt detected. Aborting.")
                for connection in active_connections:
                    connection['kill_signal'] = True
                sleep(3)
                break

    def cliThreadTapReadFunction(self, conn):
        # Check for packets in tap interface and send them to every active connection
        print("Tap thread started")
        while True:
            try:
                # +20 for ethernet headear
                packet = self.tap.read()
                buf = self.packet_to_bytes(packet, self.padding)
            except Exception as e:
                if e.args[0] == errno.EAGAIN or e.args[0] == errno.EWOULDBLOCK:
                    # Not an actual error, just no data to read yet
                    # (this is expected, wait some more)
                    # If we wish to insert a "fake packet", fill 'buf'
                    # Otherwise, "continue", forcing a new tap read
                    if shouldSendFakePacket() and self.fakepackets == 1:
                        fake_packet = fakePacket()
                        buf = self.packet_to_bytes(
                            fake_packet, self.padding, fake_packet=True)
                    else:
                        # we don't want to send a fake packet, and we don't have real packet
                        # wait a bit and try to read the tap again:
                        sleep(0.1)
                        continue
                else:
                    # Actual error - raise!
                    print(e)
                    raise
            try:
                conn.send(buf)
                self.pkts_rcvd[0] = self.pkts_rcvd[0]+1
            except OSError as exc:
                print("Error while sending data".format())
                if exc.errno == errno.EPIPE:
                    print("Broken pipe. Sending kill signal...")

    # assume connection is blocking
    # version1.3
    def get_packet_from_tls(self, conn):
        # get first 3 bytes with type and 2 byte big endian int
        fake_mask = b'\x01'
        padd_mask = b'\x02'

        data = conn.recv(3)
        if data and len(data) == 3:
            check = data[0]
            padded = ((check & padd_mask[0]) == padd_mask[0])
            fake = ((check & fake_mask[0]) == fake_mask[0])

            packet_length = int.from_bytes(data[1:3], "big")

            if padded:
                padding_size = conn.recv(2)

            packet = conn.recv(packet_length)

            if padded:
                padding_length = int.from_bytes(padding_size, "big")
                padding = conn.recv(padding_length)

            if fake:
                
                if padded: 
                    print("--> Fake padded packet:")
                    print("   Byte 0 data = " + str(data[0]) + "   Byte 1 data = " + str(data[1]) + "   Byte 2 data = " + str(data[2]) + "   Byte 3 data = " + str(
                            padding_size[0]) + "   Byte 4 data = " + str(padding_size[1]) + "  Packet = " + str(packet) + "  Padding = " + str(padding))
                else:
                    print("--> Fake packet:")
                    print("   Byte 0 data = " + str(data[0]) + "   Byte 1 data = " + str(data[1]) + "   Byte 2 data = " + str(data[2]) + "  Packet = " + str(packet))
                
                return False
            elif packet_length > 0:
                
                if padded: 
                    print("--> True padded packet:")
                    print("   Byte 0 data = " + str(data[0]) + "   Byte 1 data = " + str(data[1]) + "   Byte 2 data = " + str(data[2]) + "   Byte 3 data = " + str(
                            padding_size[0]) + "   Byte 4 data = " + str(padding_size[1]) + "  Packet = " + str(packet) + "  Padding = " + str(padding))
                else:
                    print("--> True packet:")
                    print("   Byte 0 data = " + str(data[0]) + "   Byte 1 data = " + str(data[1]) + "   Byte 2 data = " + str(data[2]) + "  Packet = " + str(packet))
                
                return packet
        return False

    def packet_to_bytes(self, packet, add_padding=True, max_length=300, fake_packet=False):
        # First byte:
        # bit mask -- 0001 if fake, 0010 if padding.
        # real packet without padding == 0
        # fake packet without padding == 1
        # real packet with padding == 2
        # fake packet with padding == 3
        """
        fake_mask = b'\x01'
        padd_mask = b'\x02'
        byte1 = bytes([(add_padding * padd_mask)[0] |
                       (fake_packet * fake_mask)[0]])
        bb1 = bytearray(byte1)
        """
        if fake_packet and add_padding:
            bb1 = bytearray(b'\x03')
        elif add_padding:
            bb1 = bytearray(b'\x02')
        elif fake_packet:
            bb1 = bytearray(b'\x01')
        else:
            bb1 = bytearray(b'\x00')

        # 2 byte big endian int with actual size.
        pkt_len = len(packet)
        b_packet_length = pkt_len.to_bytes(2, byteorder='big')
        bb2 = bytearray(b_packet_length)

        if add_padding:
            if pkt_len < max_length:
                pad_len = max_length - pkt_len
            else:
                pad_len = 0
            padd = b'\x00' * pad_len

            b_padding_length = pad_len.to_bytes(2, byteorder='big')
            bb3 = bytearray(b_padding_length)

            bb4 = bytearray(packet)

            bb5 = bytearray(padd)

            return bytes(bb1+bb2+bb3+bb4+bb5)
        else:
            bb3 = bytearray(packet)
            return bytes(bb1+bb2+bb3)

    def cliTapWriteFunction(self, conn):
        while True:
            try:
                data = self.get_packet_from_tls(conn)
                if data:
                    self.tap.write(data)
                    self.pkts_sent += 1
                    print("\rPackets sent:\t{:7d} | Packets received:\t{:7d}".format(
                        self.pkts_sent, self.pkts_rcvd[0]), end='')
            except Exception as e:
                print("Exception occurred " + str(e))
                raise
                break

    def cli_start_new_client(self):
        self.server_addr = resolve_hostname(self.args.server_addr)
        print("Connecting to TLS server at " + self.server_addr)
        context = ssl.create_default_context(
            ssl.Purpose.SERVER_AUTH, cafile=self.server_cert)
        context.load_cert_chain(
            certfile=self.client_cert, keyfile=self.client_key)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn = context.wrap_socket(
            s, server_side=False, server_hostname=self.server_sni_hostname)
        conn.connect((self.server_addr, self.server_port))
        print("SSL Connection Established.")
        self.tap.init(self.pkts_rcvd)
        t = threading.Thread(
            target=self.cliThreadTapReadFunction, args=(conn,))
        t.daemon = True
        t.start()
        self.cliTapWriteFunction(conn)


tls = TLSTunnel()

tls.initialize()
# tls.create_tap()

if tls.args.mode == 'client':
    while (True):
        try:
            tls.cli_start_new_client()
        except Exception as e:
            print(
                "Fail to establish connection or connection closed. Waiting a bit before retrying. " + str(e))
            sleep(5)
elif tls.args.mode == 'server':
    tls.create_tap()
    import token_bucket

    print("tb", tls.tb_rate, tls.tb_burst)
    tls.buckets = token_bucket.Limiter(
        tls.tb_rate, tls.tb_burst, token_bucket.MemoryStorage())

    # start tap reading and sending to clients via TLS
    tap_thread = threading.Thread(target=TLSTunnel.srvThreadTapReadFunction, args=(tls,
                                                                                   tls.tap, tls.active_connections,))
    tap_thread.daemon = True
    tap_thread.start()

    # start server thread waiting for new clients and spawn new tap read from client and write to tap
    t = threading.Thread(target=tls.srvThreadServerFunction, args=(
        tls.args.listen_addr, tls.args.listen_port, tls.active_connections, tls.buckets,))
    t.daemon = True
    t.start()

    # printout stats and don't exit
    while True:
        sleep(30)
        print("\nActive connections:")
        for i, connection in enumerate(tls.active_connections):
            print("{} - {}:{} ({})".format(i,
                                           connection['ip'], connection['port'], connection['CN']))

    else:
        print("Unnown mode -- choose between client and server")

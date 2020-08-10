#!/usr/bin/env python3
#   Description:
#       For usage instructions run the script with no parameters
#

#   TODO: add UDP option. More than one port.
#   Demo Version.

from scapy.all import *
from cryptography.fernet import Fernet
import argparse
import sys


class PortKnocking(object):

    def __init__(self, args: list):
        self._parse_args(args)

    def _parse_args(self, args: list):
        parser = argparse.ArgumentParser(add_help=True, description="Client side of the portknocking process. "
                                                                    "A sequence of SIN/ACK/RST flags are decided by "
                                                                    "the server side.")
        parser.add_argument('host', metavar='[host:port]',
                            help='Hostname or IP address with port of the host to knock on.')
        parser.add_argument('-l', '--localIp', help='ip of the client', required=True)
        parser.add_argument('-n', '--numberOfknocks', help='number of flags to send(default is 4): -n 4', default=4,
                            required=False)
        parser.add_argument('-f', '--flag', help='type of a flag to send: -f ACK or -f SYN or -f RST.', required=True)
        parser.add_argument('-c', '--cipher', help='cipher Key to encrypt a password (avoid MITM).', required=False)
        parser.add_argument('-p', '--password',
                            help='Password to authenticate with the remote server(will be encrypted).', required=True)

        args = parser.parse_args(args)
        self.host_port = args.host
        self.localIp = args.localIp
        self.numberOfknocks = args.numberOfknocks
        self.typeOfFlag = args.flag
        self.cipher = args.cipher
        self.password = args.password


    def generate_packet(self, flag):
        global host, port_no
        host, port_no = self.host_port.split(':', 2)
        scapy_packet = IP(dst=host, src=self.localIp) / TCP(dport=int(port_no), flags=flag)
        return scapy_packet

    def create_packets(self):
        if self.typeOfFlag == 'ACK' or self.typeOfFlag == 'A':
            all_packets = self.generate_packet(flag='A')
        elif self.typeOfFlag == 'SYN' or self.typeOfFlag == 'S':
            all_packets = self.generate_packet(flag='S')
        elif self.typeOfFlag == 'RST' or self.typeOfFlag == 'R':
            all_packets = self.generate_packet(flag='R')
        return all_packets

    def encrypt_password(self):
        cipher = Fernet(self.cipher)
        bytes_password = bytes(self.password, encoding='utf-8')
        token = cipher.encrypt(bytes_password)
        return token

    def send_packets(self):
        token = self.encrypt_password()
        packets_to_send = self.create_packets()
        send(IP(dst=host, src=self.localIp) / ICMP() / "    " / token)
        time.sleep(1)
        send(packets_to_send, count=self.numberOfknocks)


if __name__ == '__main__':
    PortKnocking(sys.argv[1:]).send_packets()

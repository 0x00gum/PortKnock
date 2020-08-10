from cryptography.fernet import Fernet
import argparse
import sys
import time
import subprocess


class PortKnocking(object):

    def __init__(self, args: list):
        self._parse_args(args)

    def _parse_args(self, args: list):
        parser = argparse.ArgumentParser(add_help=True, description="Server side of the portknocking process. "
                                                                    "Server side detriments the type of a flag,"
                                                                    "number of knocks "
                                                                    "and the password to authanticate with the client.")
        parser.add_argument('-l', '-listen', type=int,
                            help='Port to listen for incoming knocks.',
                            required=True)
        parser.add_argument('-i', '--clientIp', help='client Ip.', required=True)
        parser.add_argument('-n', '--numberOfknocks',
                            help='number of knowks to except form the client(default is 4): -n 4',
                            default=4,
                            required=False)
        parser.add_argument('-f', '--flag',
                            help='set a type of a flag to except form the client: -f ACK or -f SYN or -f RST.',
                            required=True)
        parser.add_argument('-c', '--cipher', help='cipher Key to decrypt the password (avoid MITM).', required=False)
        parser.add_argument('-p', '--password',
                            help='Set a password to authenticate with the client.',
                            required=True)
        parser.add_argument('-t', '--timeout', type=int, default=5,
                            help='How many minutes to wait on hanging the SSH connection. Default is 5 min.',
                            required=False)
        args = parser.parse_args(args)
        self.port = args.l
        self.clientIp = args.clientIp
        self.numberOfknocks = args.numberOfknocks
        self.typeOfFlag = args.flag
        self.cipher = args.cipher
        self.password = args.password
        self.timeout = args.timeout

    def get_encrypted_string(self):
        
        # Server is listening for encrypted password and returns the value.
        print("[+] Server is listening for incoming knowcks.")
        data = sniff(count=1, filter=f"icmp and host {self.clientIp}")
        firstIndex = str(data[0])
        for i in firstIndex:
            li = list(firstIndex.split(" "))
        string_to_decrypt = str(li[4])
        return string_to_decrypt

    def decrypt_icmp_packet(self):
        # Decrpyting the icmp packets sent by the client by using Fernet.
        string_to_decrypt = self.get_encrypted_string()
        cipher = Fernet(self.cipher)
        encoded = string_to_decrypt.encode()
        decrypted_text = cipher.decrypt(encoded)
        return decrypted_text

    def decrypt_password(self):

        # Obviously decrypting the password! 
        decrypted_text = self.decrypt_icmp_packet()
        bytes_pass = bytes(self.password, encoding='utf-8')
        if decrypted_text == bytes_pass:
            return True
        elif decrypted_text != bytes_pass:
            return False

    def sniff_packets(self):
        """
            This function sniffs the packets form the client if
            the password is correct.
        """
        if self.decrypt_password():
            print("[+] Password is correct!")
            sniff_filter = f"tcp and host {self.clientIp} and port {self.port}"
            sniffed_packets = sniff(count=self.numberOfknocks * 2, filter=sniff_filter)
            if sniffed_packets != " ":
                print("[+] Opening SSH port for:", self.timeout, "minutes.")
                try:
                    if self.timeout > 0:
                        subprocess.call(['service', 'ssh', 'start'])
                        time.sleep(self.timeout * 60)
                        subprocess.call(['service', 'ssh', 'stop'])
                except KeyboardInterrupt:
                    subprocess.call(['service', 'ssh', 'stop'])
                    sys.exit()

# Starting the program with arguments!
PortKnocking(sys.argv[1:]).sniff_packets()

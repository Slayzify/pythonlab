#!/usr/bin/env python3

import scapy.all as scapy
import optparse


def load_args():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="IP Range to scan, with subnet. (ie. 192.168.1.0/24)")
    (opt, args) = parser.parse_args()

    if not opt.target:
        parser.error("[-] Target range is missing.\nUse -h or --help to see options.")

    return opt


def scan(opt):
    broadcast = scapy.Ether(dst="FF:FF:FF:FF:FF:FF")
    arp = scapy.ARP(pdst=opt.target)
    full_arp_request = broadcast/arp

    print("[+] Scanning for {0}...".format(opt.target))

    ans = scapy.srp(full_arp_request, timeout=2, verbose=False)[0]

    print("[+] Found {0} Host(s)".format(len(ans)))

    if len(ans) > 0:
        clients_list = []
        for element in ans:
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            clients_list.append(client_dict)

        return clients_list
    else:
        exit()


def print_result(clients):
    print("----------------------------------------")
    print("   IP\t\t   MAC Address")
    print("----------------------------------------")

    for element in clients:
        print("{0}\t{1}".format(element["ip"], element["mac"]))


if __name__ == "__main__":
    print_result(scan(load_args()))

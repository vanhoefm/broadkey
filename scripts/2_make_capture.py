#!/usr/bin/env python2
from scapy.all import *
import sys

got_beacon = False
got_data = False
capture = []

def process_packet(p):
	global got_beacon
	global got_data
	global capture

	if p.addr1 != "ff:ff:ff:ff:ff:ff":
		return
	if p.addr2 != "38:2c:4a:c1:69:bc":
		return

	if not got_beacon and Dot11Beacon in p:
		print "\n[+] Got a beacon"
		got_beacon = True
	elif not got_data and Dot11WEP in p:
		print "\n[+] Got an encrypted broadcast packet"
		got_data = True
	else:
		sys.stdout.write(".")
		sys.stdout.flush()

	capture.append(p)


def main():
	"""
	You can also use tshark to capture only broadcast data from the Access Point:

		sudo tshark -i wlp0s20u1 -w testcapture.pcap -F pcap "wlan addr1 ff:ff:ff:ff:ff:ff && wlan addr3 38:2c:4a:c1:69:bc"

	But this scripts let's you know wheb a Beacon and Broadcast Data frame has been captured,
	and then automatically saves the capture and terminates.
	"""
	global got_beacon
	global got_data
	global capture

	if len(sys.argv) != 2:
		print "Usage: %s interface" % sys.argv[0]
		quit(1)

	print "Capturing frames ..."
	conf.iface = sys.argv[1]
	sniff(iface=conf.iface, prn=process_packet, stop_filter= lambda p: got_beacon and got_data)

	capname = "capture.pcap"
	wrpcap(capname, capture)
	print "[+] Wrote capture to %s\n" % capname


if __name__ == "__main__":
	main()


#!/usr/bin/python
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

localip = [x[4] for x in scapy.all.conf.route.routes if x[2] != '0.0.0.0'][0]
log = open('postanalyzer.log', 'ab')

prev_ack = 0
prev_body = ''
interface = 'wlan0'

def cb(pkt):
	global prev_ack, prev_body

	post_found = 0
	if pkt.haslayer(Raw):

		load = repr(pkt[Raw].load)[1:-1]

		try:
			headers, body = load.split(r"\r\n\r\n", 1)
		except:
			headers = load
			body = ''

		ack = pkt[TCP].ack
		if prev_ack == ack:
			newBody = prev_body+headers
			print 'Fragment found; combined body:\n\n', newBody
			print '-----------------------------------------'
			prev_body = newBody
			log.write('Fragment found; combined body:\n\n'+newBody+'\n-----------------------------------------\n')
			return

		header_lines = headers.split(r"\r\n")
		for h in header_lines:
			if 'post /' in h.lower():
				post_found = h.split(' ')[1].split(' ')[0]
		if post_found:
			for h in header_lines:
				if 'host: ' in h.lower():
					host = h.split(' ')[1].split(' ')[0]
					print 'URL:',host+post_found
				elif 'referer: ' in h.lower():
					print h

			prev_body = body
			prev_ack = ack

			if body != '':
				print '\n'+body
				print '-----------------------------------------'

			log.write(pkt.summary()+'\n')
			for h in header_lines:
				log.write(h+"\n")
			if body != '':
				log.write(body)
			log.write('\n-----------------------------------------\n')

sniff(iface=interface, filter='tcp port 80', prn=cb, store=0)

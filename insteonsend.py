#!/usr/bin/env python
"""
@Author: mays85
@Date: July 2016
@ver: 1.0
@Description: Most of this code was written by Evil Pete (Peter Shipley). Mays85 modified portions, but mainly
in an effort to "pretty-up" the code. It works great, though!
Of note, Mays85 decided to take out all of the argument options that Shipley had, allowing the sending of the raw data.
Figure out what the packet flags and order for yourself.

A good number of these functions are called in  insteonscanner.py
"""

import argparse
from pktcreator import pkt_crc  # needed for calculating crc before it's sent.
from rfcatmod import *

rawpkt = False
verbose = False
interface = 0

preamble = "0101010101"
postamble = "010101010101010101010101010101010101010101010101"


def read_raw_pkt(plist):
	a = list()
	for i in plist:
		if i == ":":
			continue
		a.append(int(i, 16))

	return a


def init():
	parser = argparse.ArgumentParser(add_help=True,
									epilog="example:\n\t# ./insteonsend.py -v -r 05 : 33 d3 32 : de c2 33 : 11 ff",
									description='generate an Insteon packet')

	parser.add_argument('-i', '--interface', help='USB interface', default=0)

	parser.add_argument("-v", "--verbose", action="store_true", help="verbose mode")

	parser.add_argument("-r", "--raw", dest="raw",
					action='store_true',
					help="Raw Packet")

	args, unknown_args = parser.parse_known_args()

	if args.verbose:
		# go get the verbose variable
		global verbose
		verbose = args.verbose

	if args.raw:
		# go get the rawpkt variable.
		global rawpkt
		rawpkt = args.raw

	if args.interface:
		global interface
		interface = int(args.interface)
	return unknown_args


def manchester_encode(*args):
	"""
	:param args: input  string of "1011"
	:return: output  string of "01100101"
	"""
	return_bits = list()

	# nest of for loops since args may be a list of strings
	for x in args:
		for y in x:
			for z in y:
				if z == "0":
					return_bits.append("10")
				elif z == "1":
					return_bits.append("01")
				elif z == "-":
					return_bits.append(z)
				else:
					print "char=",z
					raise ValueError("invalid bit '{:!s}'".format(z))

	return "". join(return_bits)


def assemble_packet(dat, firstmarker=1):
	ret = list()
	if isinstance(dat[0], int):

		dat_int = dat[:]
	else:
		print "dat is not of an int list...quiting"
		exit(0)
	# preamble defined already, make it manchester and append
	m = manchester_encode(preamble)
	ret.append(m)

	# now...time to encode the rest of the bytes.
	dat_len = len(dat_int)
	if firstmarker == 1:
		ret.append('11')

		firstb = dat_int.pop(0)
		x = "{:08b}".format(firstb)[::-1]
		m = manchester_encode("11111", x)
		ret.append(m)

		if firstb & 0b00010000:
			c = 31
		else:
			c = 11
	else:
		c = dat_len - 1

	for x in xrange(len(dat_int)):
		rc = "{:05b}".format(c)[::-1]
		c -= 1
		rx = "{:08b}".format(dat_int[x])[::-1]
		ret.append('11')
		m = manchester_encode(rc, rx)
		ret.append(m)

	m = manchester_encode(postamble)
	ret.append(m)

	ret_str = "".join(ret)
	# print ret_str
	return ret_str


def invert_pkt(p):
	p = p.replace('0', 'A')
	p = p.replace('1', '0')
	p = p.replace('A', '1')
	return p


def b_to_binstr(dat):
	if verbose:
		print "bits sent:", dat

	r = bytearray(int(dat[x:x + 8], 2) for x in range(0, len(dat), 8))
	return r


def send_pkt(device, dat):
	bs = b_to_binstr(dat)
	device.RFxmit(bs)
	# time.sleep(60 / 1000)  # is there a reason for sleeping after sending??
	device.strobeModeIDLE()


def main():
	av = init()
	global rawpkt
	if rawpkt:
		if len(av) == 0:
			print "must have either 9 or 23 args in hex"
			exit(1)
		pktlistdecimal = read_raw_pkt(av)
		if len(pktlistdecimal) == 9 or len(pktlistdecimal) == 23:
			pktcrc = pkt_crc(pktlistdecimal)
			pktlistdecimal.append(pktcrc)

			if verbose:
				print "pkt crc: ", pktcrc
				print "full pkt in decimal: ", pktlistdecimal
		else:
			print "must have either 9 or 23 args in hex"
			exit(1)

	if verbose:
		print >> sys.stderr, "full pkt list in hex: ", ["{:02X}".format(j) for j in pktlistdecimal]

	pkttosend = assemble_packet(pktlistdecimal)
	# print "{:s}".format(pkttosend)

	pkttosendinverted = invert_pkt(pkttosend)
	# print "{:s}".format(pkttosendinverted)

	# AT THIS POINT, pkttosendinverted HAS THE CORRECT INFORMATION TO MAKE IT
	# THROUGH THE PARSER ./print_pkt.py. SO...SHOULD BE GOOD TO PUT ON THE WIRE
	# AND SEND IT...WILL HAVE TO MAKE SURE THAT MY OWN RECEIVER WILL BE ABLE
	# TO HEAR IT.
	device = configure_rfcat(interface)
	send_pkt(device, pkttosendinverted)


if __name__ == "__main__":
	main()
	exit(0)

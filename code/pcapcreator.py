#!/usr/bin/env python
"""
@Author: mays85
@date: June 2016
@version: 1.0
@Description: This reads in a rawfile and outputs a correctly formatted pcap file.
-- The first line of the input file is a asctime(localtime()) string. The second line is a string of bytes representing
	an Insteon packet. Repeat to end of file.

-- Input file format example:
Tue Jun 21 13:10:03 2016
01 E7 5C 2F DE C2 33 11 FF 44

"""
import binascii
from time import *
import time
from pktcreator import *


# writes the string of bytes to the file in the arguments.
def writebytestringtofile(bytestring, filehandle):
	bytelist = bytestring.split()
	bytes = binascii.a2b_hex(''.join(bytelist))
	filehandle.write(bytes)
	filehandle.flush()


# a helper function to get the length of the bytes. necessary for pcap file information.
def getbytelength(str1):
	return len(''.join(str1.split())) / 2


# conversion function. Takes timestamp information and a message and gives back a pcap formated sub-packet.
def rawtopcap(timestamp, message):

	# pcap packet header that must preface every packet
	pcap_packet_header = (# 4 bytes of date/time information that gets figured out later.
						'00 00 00 00'   # milliseconds. unfortunately, it looks like rfcat doesn't do millis.
						'XX XX XX XX'   # Frame Size (little endian)  
						'YY YY YY YY')  # Frame Size (little endian)
	pcap_len = getbytelength(message)
	hex_str = "%08x"%pcap_len
	# reverse the hex so that it's the correct format (little endian)
	reverse_hex_str = hex_str[6:] + hex_str[4:6] + hex_str[2:4] + hex_str[:2]
	pcaph = pcap_packet_header.replace('XX XX XX XX',reverse_hex_str)
	pcaph = pcaph.replace('YY YY YY YY',reverse_hex_str)

	# get the time. going to have to change this to be reading from either the screen or a file.
	# the below conversion takes a string input of time and spits out hex. beautiful. pay attention to the
	# format stuff at the end. This page was helpful https://docs.python.org/3/library/time.html
	timehex = hex(int(time.mktime((time.strptime(timestamp, '%a %b %d %H:%M:%S %Y')))))

	# but you gotta strip the "0x" from the first part of the hex and make it a string.
	timehexstr_rvrs = str(timehex)[2:]

	# now time to re-order that hex to be reversed because little endian. use same method as above.
	timehexstr = timehexstr_rvrs[6:] + timehexstr_rvrs[4:6] + timehexstr_rvrs[2:4] + timehexstr_rvrs[:2]

	# put it all together in a string of bytes.
	bytestring = timehexstr + pcaph + message

	# return those bytes to the overall bytestring
	return bytestring


def createreadablefile(inputfilename, outputfilename):
	"""
	:param inputfilename: file name to read from
	:param outputfilename: file name to write to
	:return: None
	"""
	# i know this file exists because I just used it. No need to check if it exists.
	fin = open(inputfilename, "r")
	readout = open(outputfilename, "w")

	devicestosave = list()
	# if the file exists, read the devicestosave listed into devicestosave list. reopen file and write devices again.
	try:
		devicesfile = open("insteon.devices", "r")

		for x in devicesfile:
			devicestosave.append(x.strip("\n"))
		devicesfile.close()
		devicesfile = open("insteon.devices", "w")
		for device in devicestosave:
			devicesfile.write(device+"\n")
	except IOError:
		devicesfile = open("insteon.devices", "w")

	finally:
		pass

	# start reading from the readable file.
	for _timestamp_ in fin:
		_rawData_ = next(fin)
		_rawData_ = _rawData_.strip("\n")
		subpackets = parse_insteon_pkt(_rawData_, _timestamp_)
		if subpackets is not None:
			for packet in subpackets:
				# validcrc is set to one at the end of parse_insteon_pkt if the packet is full, etc etc.
				if packet.validcrc == 1:
					# generate the readable lines necessary.
					readablebytes = _timestamp_
					readablebytes += packet.hex_str + "\n"
					# send readable bytes to file.
					readout.write(readablebytes)
					# there is always a device ID in a message (first device ID set)
					if packet.hex_str[3:11] not in devicestosave:
						devicesfile.write(packet.hex_str[3:11]+"\n")
						devicestosave.append(packet.hex_str[3:11])
					# however, for some messages, (group, broadcast, etc), there is not a device ID
					# in the second device ID set. For the purposes of keeping track of IDs, I don't care.
					# C is group broadcast standard
					# 8 is broadcast standard
					# D is group broadcast extended
					# 9 is broadcast extended
					if packet.hex_str[0] is not "C" and not "8" and not "D" and not "9":
						if packet.hex_str[12:20] not in devicestosave:
							devicesfile.write(packet.hex_str[12:20]+"\n")
							devicestosave.append(packet.hex_str[12:20])

	print "known device IDs (could be from previous captures) : ", devicestosave


def createpcap(inputfilename, outputfilename):
	# bytestring is intially set to the global pcap header. 
	# look here for more info: 
	# http://www.codeproject.com/Tips/612847/Generate-a-quick-and-easy-custom-pcap-file-using-P
	bytestring = ('D4 C3 B2 A1'   # magic numbers
					'02 00'         # File format major revision (i.e. pcap <2>.4)  
					'04 00'         # File format minor revision (i.e. pcap 2.<4>)   
					'00 00 00 00'   # timezone info. leaving blank.   
					'00 00 00 00'   # accuracy of timestamps
					'FF FF 00 00'   # max length of captured packet
					'93 00 00 00') # Datalink type 93 = DLT_USR 147 -- the WireShark non-defined protocol.
	outfilehandle = open(outputfilename, "wb")
	writebytestringtofile(bytestring, outfilehandle)


	# open the readable file
	raw_file = open(inputfilename, "r")
	# going to tell user how many packets we got...
	counter = 0
	# start by reading the first thing (a timestamp)
	for __timestamp__ in raw_file:
		__timestamp__ = __timestamp__.strip("\n")  # gotta strip the newline
		__rawdata__ = next(raw_file)
		__rawdata__ = __rawdata__.strip("\n")  # gotta strip the newline

		# send the timestamp and rawdata to the converter function, then add that returning info to bytestring.
		bytestring = rawtopcap(__timestamp__, __rawdata__)
		writebytestringtofile(bytestring, outfilehandle)
		counter += 1

	# write the entire bytestring to the outputfile. hopefully that bytestring doesn't get too big.....

	print "received: " + str(counter) + " packets"

# for when I want to run this file individually.
# createpcap("rawfile.txt","output.pcap")

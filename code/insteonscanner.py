#!/usr/bin/env python
"""
@Author: mays85
@Date: July 2016
@ver: 1.0
@Description: Read from the known devices file. Ping and do an ID request from each device to every other device.
It takes some time, but this is the main enumeration process.
"""


from insteonsend import *


def parseargs():
	"""
	:return: the arguments.
	"""
	parser = argparse.ArgumentParser(
		description='Spoof ping and ID request commands from the insteon.devices list. This file must'
		            'already exist and valid device IDs must be in this list to work.')

	parser.add_argument('-i', '--interface', help='USB interface', default=0)
	return parser.parse_args()


def getdevicelist():
	"""
	:return: list of devices from the insteon.devices file, if it exists.
	"""
	devices = list()
	try:
		devicesfile = open("insteon.devices", "r")
		for x in devicesfile:
			devices.append(x.strip("\n"))
		devicesfile.close()
	except:
		# if the file doesn't exist, tell user to run insteondump.py -d -o output.pcap to save devices.
		print "program needs insteon.devices file to exist. That file is created by running " \
		      "./insteondump.py -d -o output.pcap and listening for an Insteon action."
		sys.exit(0)
	finally:
		pass

	return devices


def buildpackets():
	"""
	:return: list of commands to ping and perform ID request for each device in the devices file.
	"""
	# get the list of devices.
	devicelist = getdevicelist()

	# start setting up the list of packets.
	packetslist = list()

	# individual statements will be held here.
	statement = list()

	# for simplifying this to a for-loop.
	command1 = list()
	command1.append("0F")  # ping command
	command1.append("10")  # ID request command

	# i'm going to scan through each device for each device.
	for device1 in devicelist:
		for device2 in devicelist:
			# don't care about having the same device ID for both addresses..but maybe I should try??
			if device1 is not device2:
				for command in command1:
					# build each command that I want to sent.
					statement.append("0F")  # for now, standard direct messages.
					statement.append(device1[0:2])
					statement.append(device1[3:5])
					statement.append(device1[6:])
					statement.append(device2[0:2])
					statement.append(device2[3:5])
					statement.append(device2[6:])
					statement.append(command)
					statement.append("00")
					packetslist.append(statement[:])
					statement = list()

	# packetlist contains full list of commands (without CRC).
	# now that I have all the commands in the packetslist. I need to convert those lists to integers and calc the crc.
	finalpackets = list()
	for packet in packetslist:
		pktlistdecimal = read_raw_pkt(packet)
		if len(pktlistdecimal) == 9 or len(pktlistdecimal) == 23:
			pktcrc = pkt_crc(pktlistdecimal)
			pktlistdecimal.append(pktcrc)
			finalpackets.append(pktlistdecimal)
			# have to reset the pktlistdecimal for some reason....
			pktlistdecimal = list()

	# will return both the final packets in decimal form and packets list for nice printing later.
	return finalpackets, packetslist


def main():
	# create pre-gened packets from insteon.devices list and command table
	# I really just care about ping (OF 00) and ID Request (10 00)
	pktlistdecimal, pktlisthex = buildpackets()

	# give me a yardstick.
	args = parseargs()
	yardstick = configure_rfcat(int(args.interface))

	# for every packet in the packet list, assemble the binary and send. Will wait 1/2 second between sends for
	# listener  see what comes back.
	for pkt in pktlistdecimal:
		pkttosend = assemble_packet(pkt)
		pkttosendinverted = invert_pkt(pkttosend)
		send_pkt(yardstick, pkttosendinverted)
		# send, wait for responses. 1/2 second should be enough time.
		# hopefully the live capture tool and keep up!
		time.sleep(.5)
		index = pktlistdecimal.index(pkt)
		print "sent: ", pktlisthex[index]

	yardstick.setModeIDLE()


# run main.
if __name__ == "__main__":
	main()
	sys.exit(1)
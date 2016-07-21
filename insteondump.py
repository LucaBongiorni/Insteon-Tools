#!/usr/bin/env python
"""
@Author: mays85
@date: July 2016
@version: 2.0
@Description: This is the main listener program. Users can either:
1) Listen "off-line" -- save all the traffic to a .raw file, then convert that traffic into readable
	Insteon and, finally converting it to .pcap file.
OR
2) Listen "live" -- covert raw data live, and using named pipe, send data to Wireshark live.

"""

from argparse import *
from pcapcreator import *
from pktcreator import *
from rfcatmod import *
from insteonanalyzer import *
import re


def parseargs():
	"""
	:return: the arguments.
	"""
	parser = ArgumentParser(
		description='Read Insteon commands from RfCat and dump to pcap file or named pipe for WireShark. '
		            'Examples:\t./insteondump.py -o capture -- for off-line mode. '
		            '\t\t ./insteondump.py -l -p mypipe -- where mypipe is a pre-named pipe. mkfifo mypipe')

	# keep it simple.
	parser.add_argument('-i', '--interface', help='USB interface to use. Default is 0', default=0)
	parser.add_argument('-l', '--livemode', help='Do capture with live mode. Must provide -p <pipename>'
	                                             'for this mode.', action='store_true')
	parser.add_argument('-p', '--pipename', help='named pipe for wireshark capture. mkfifo <pipename> first,'
	                                             'then use -p <pipename> here.')
	parser.add_argument('-o', '--outputFileName', help='Output file name (will be pcap format). '
	                                                   'Assumed to be used in \'offline\' mode')

	return parser.parse_args()


def keystop(delay=0):
	"""
	the <enter> pressed function.
	:param delay: time to wait before registering the command?
	:return: the length of the command. Not sure why...
	"""
	return len(select.select([sys.stdin], [], [], delay)[0])


def updatescreen(devicelist):
	"""
	might be a simple function, but could be helpful in the future.
	:param devicelist: the global devicelist.
	:return: n/a
	"""
	# found this line online somewhere. it works great!
	os.system('cls' if os.name == 'nt' else 'clear')
	devicelistprint(devicelist)


def livecapture(devicelist, yardstick, pipename):
	"""
	the function that does the live listening / screen updating.
	:param devicelist: the devicelist to be maintained throughout the live capture
	:param yardstick: the yardstick object used.
	:param pipename: a named pipe to send the data.
	:return: n/a
	"""

	# I would normally do this with the an open(filename, "a") function, but I don't care to save
	# duplicate device IDs. So I have to read the file first, saving each address, then re-open it in 'w' mode
	# to write over everything.
	devicestosave = list()
	try:
		# if the file exists, open it, read devices, save them, close file. reopen file in 'w' mode and write devices.
		devicesfile = open("insteon.devices", "r")

		for x in devicesfile:
			devicestosave.append(x.strip("\n"))
		devicesfile.close()

		# reopening file.
		devicesfile = open("insteon.devices", "w")
		for device in devicestosave:
			devicesfile.write(device + "\n")
	except IOError:
		# means that the file didn't exist, so just open it in write mode.
		devicesfile = open("insteon.devices", "w")
	finally:
		# if there's an error here, well...woops?
		pass

	# need the write in byte mode.
	mypipe = open(pipename, 'wb')

	# magic numbers, etc for pcap format header. Wireshark needs this at the beginning of the pipe.
	bytestring = "d4 c3 b2 a1 02 00 04 00 00 00 00 00 00 00 00 00 ff ff 00 00 93 00 00 00"

	# send bytes to pipe.
	writebytestringtofile(bytestring, mypipe)

	while not keystop():
		try:
			rawdata, timestamp = yardstick.RFrecv(timeout = 2000)
			timestampstring = str(asctime(localtime(timestamp)))
			_bytes_ = ''.join("{0:08b}".format(x) for x in bytearray(rawdata))

			subpackets = parse_insteon_pkt(_bytes_, timestampstring)
			if subpackets is not None:
				for packet in subpackets:
					# I really care about valid packets here.
					if packet.validcrc == 1:
						timestamp = packet.timestamp
						readablepacket = packet.hex_str

						# analyze the packet
						analyzepacket(devicelist, readablepacket)

						# update the screen
						updatescreen(devicelist)

						# get ready to send this to a pipe.
						bytestring = rawtopcap(timestamp, readablepacket)
						# send to the pipe.
						writebytestringtofile(bytestring, mypipe)

						# save any IDs for later spoofing.
						if packet.hex_str[3:11] not in devicestosave:
							devicesfile.write(packet.hex_str[3:11] + "\n")
							devicesfile.flush()
							devicestosave.append(packet.hex_str[3:11])
						# however, for some messages, (group, broadcast, etc), there is not a device ID
						# in the second device ID set. For the purposes of keeping track of IDs, I don't care.
						# C is group broadcast standard
						# 8 is broadcast standard
						# D is group broadcast extended
						# 9 is broadcast extended
						if packet.hex_str[0] is not "C" and not "8" and not "D" and not "9":
							if packet.hex_str[12:20] not in devicestosave:
								devicesfile.write(packet.hex_str[12:20] + "\n")
								devicesfile.flush()
								devicestosave.append(packet.hex_str[12:20])
			devicesfile.flush()

		except KeyboardInterrupt:
			print "Please press <enter> to stop"

		except IndexError:
			print "Index fail"

		except ChipconUsbTimeoutException:
			# print "ChipconUsbTimeoutException"
			# simply means the yardstick could have not "heard" anything that matched the packet looked for.
			pass

		finally:
			pass

	# ensure the yardstick goes into idle mode
	yardstick.setModeIDLE()


# main.
def offlinecapture(yardstick, rawout):
	print "press <enter> when done, then view output file in WireShark...."
	while not keystop():
		try:
			rawdata, timestamp = yardstick.RFrecv(timeout = 2000)

			# converts the timeStamp info returned from RFrecv and turns it into a readable string.
			# important for creating / sorting / viewing in WireShark.
			timestampstring = str(asctime(localtime(timestamp)))

			# makes certain that the raw bytearray data turns into a string of 1s and 0s.
			_bytes_ = ''.join("{0:08b}".format(x) for x in bytearray(rawdata))

			# start building the raw data file. This minimizes the amount of time spent not in the RFrecv function.
			rawout.write(timestampstring + "\n")
			rawout.write(_bytes_ + "\n")

		except KeyboardInterrupt:
			print "Please press <enter> to stop"

		except IndexError:
			print "Index fail"

		except ChipconUsbTimeoutException:
			# TimeoutExceptions seem to happen when the listener hasn't gotten any data that matches the pre-amble info
			# I don't really care...just pickup and keep listening...
			# print "ChipconUsbTimeoutException"
			pass

		finally:
			pass

	# ensure the yardstick goes into idle mode
	yardstick.setModeIDLE()


def main():
	"""
	:return: Main doesn't return anything, but it can exit if the output file name is not given as an argument.
	"""
	# just get the args right away.
	args = parseargs()

	# get the RfCat and configure it.


	# see if the user wants live mode or non-live mode.
	livemode = args.livemode
	if livemode:
		# devicelist will keep track of the devices that I've seen and start building relationships.
		# needed for terminal output.
		devicelist = list()

		# better exist.
		pipename = args.pipename
		if pipename is None and not re.search("\W", pipename):
			print "Requires '-p <pipename> to direct the live capture to a named pipe. Also, only letters and numbers."
			sys.exit(0)

		print "view output file in WireShark....press <enter> when done."

		# start actually capturing stuff.
		# note: should probably do some kind of validation for the interface...

		interface = int(args.interface)
		yardstick = configure_rfcat(interface)
		livecapture(devicelist, yardstick, pipename)

	else:
		# get the output file name the user wants from args. if no output file name included, quit.
		pcapoutputfilename = args.outputFileName
		if pcapoutputfilename is None:
			print "Requires '-o <output_file_name>' to store a pcap file."
			sys.exit(0)

		if re.search("\W", pcapoutputfilename):
			print "pcap file name must only use letters and numbers. no special characters, please. "
			print "The \'.pcap\' tag will be added later."
			sys.exit(0)

		# adding the .pcap
		pcapoutputfilename += ".pcap"

		# i'm going to create 2 other temp files in addition to the pcap. call them .raw and .insteondump.
		# will be used for conversions later.
		rawoutputfilename = pcapoutputfilename.replace(".pcap", ".raw")
		insteonoutputfilename = pcapoutputfilename.replace(".pcap", ".insteondump")

		# get the rawoutput handle to give to the offlinecapture function.
		rawouthandle = open(rawoutputfilename, "w")

		# create the yardstick to give the capture function.
		yardstick = configure_rfcat(int(args.interface))

		# capture!
		offlinecapture(yardstick, rawouthandle)

		# 2 conversions.
		createreadablefile(rawoutputfilename, insteonoutputfilename)
		createpcap(insteonoutputfilename, pcapoutputfilename)

		# analyze the file for display.
		analyzefile(insteonoutputfilename)


# run main.
if __name__ == "__main__":
	main()
	sys.exit(1)
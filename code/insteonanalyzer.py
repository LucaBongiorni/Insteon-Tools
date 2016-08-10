#!/usr/bin/env python
"""
@Author: mays85
@Date: July 2016
@ver: 1.0
@Description: This module reads an Insteon packet (or a .insteondump file) from the off-line mode) and analyzes what
happened. This builds the network "map". The Device class  contains the necessary attributes per device ID.
"""

import sys, argparse, time, os


class Device(object):
	# obj for keeping track of the devices when i see the device category.
	def __init__(self, address, devcatstring=None, isresponder=False, respondstoaddress=None, iscontroller=False, controlsaddress=None,
	             isgroupcontroller=False, controllgroupaddress=None, isgroupresponder=False, respondstogroupaddress=None):
		# the address is important
		self.address = address

		# info about the device, if available.
		self.devcatstring = devcatstring
		self.devcatdescription = "unknown device type"
		if self.devcatstring is not None:
			self.devcatlookup(devcatstring)

		# on init, this device could be a responder
		self.isresponder = isresponder
		self.respondstolist = list()
		if self.isresponder:
			self.udpaterespondsdirecttolist(respondstoaddress)

		# on init, this device could be a controller
		self.iscontroller = iscontroller
		self.controlslist = list()
		if self.iscontroller:
			self.updatecontrollsdirectlist(controlsaddress)

		# contoller group info
		self.isgroupcontroller = isgroupcontroller
		self.controlgroupaddresses = list()
		if self.isgroupcontroller:
			self.updatecontrolgrouplist(controllgroupaddress)

		# responder group info
		self.isgroupresponder = isgroupresponder
		self.respondgroupaddresses = list()
		if self.isgroupresponder:
			self.updaterepondtogrouplist(respondstogroupaddress)

	def devcatlookup(self, devcatstring):
		if self.devcatstring is None:
			return "unknown device type"
		else:
			if int(self.devcatstring, 16) > len(self.devcatlookuptable):  # make sure to not get an index out of bounds.
				return "unknown device type"
			else:
				return self.devcatlookuptable[int(self.devcatstring, 16)]

	def udpaterespondsdirecttolist(self, respondstoaddress):
		if len(self.respondstolist) == 0:
			self.respondstolist.append(respondstoaddress)
		else:
			if respondstoaddress not in self.respondstolist:
				self.respondstolist.append(respondstoaddress)

	def updatecontrollsdirectlist(self, controlsaddress):
		if len(self.controlslist) == 0:
			self.controlslist.append(controlsaddress)
		else:
			if controlsaddress not in self.controlslist:
				self.controlslist.append(controlsaddress)

	def updatecontrolgrouplist(self, groupaddress):
		if len(self.controlgroupaddresses) == 0:
			self.controlgroupaddresses.append(groupaddress)
		else:
			if groupaddress not in self.controlgroupaddresses:
				self.controlgroupaddresses.append(groupaddress)

	def updaterepondtogrouplist(self, groupaddress):
		if len(self.respondgroupaddresses) == 0:
			self.respondgroupaddresses.append(groupaddress)
		else:
			if groupaddress not in self.respondgroupaddresses:
				self.respondgroupaddresses.append(groupaddress)

	devcatlookuptable = ["General Controller", "Dimmable Lighting Control", "Switched Lighting Control",
	                     "Network Bridge", "Irrigation Control", "Climate Control", "Pool and Spa control",
	                     "Sensors and Actuators", "Home Entertainment", "Energy Management", "Built-in Appliance",
	                     "Plumbing", "Communication", "Computer Control", "Window Coverings", "Access Control",
	                     "Security, Health, Safety", "Surveillance", "Automotive", "other"]

# ---------------- END OF CLASS ---------------#


def parseargs():
	"""
	:return: the arguments.
	"""
	parser = argparse.ArgumentParser(
		description='Read Insteon log file and create network "map" and categorize devices (if ID request command available)')

	#
	parser.add_argument('-i', '--inputfilename', help='Input file name. File must be of the .insteondump format')
	return parser.parse_args()


def devicelistprint(devicelist):
	if len(devicelist) == 0:
		print "no devices relationships found in capture"
	else:
		for device in devicelist:
			if device.devcatstring is not None:
				print device.address, "is a: ", device.devcatdescription
			else:
				print device.address, "is unknown"

		print
		print
		# tell user about the controllers.
		print "Controllers are:"
		for device in devicelist:
			if device.iscontroller:
				print device.address, " controls: ", device.controlslist
		print
		print
		# tell user about responders.
		print "Responders are:"
		for device in devicelist:
			if device.isresponder:
				print device.address, " responds to: ", device.respondstolist

		print
		print
		# tell user about any group controllers
		print "Group controllers are:"
		for device in devicelist:
			if device.isgroupcontroller:
				print device.address, " controls group(s): ", device.controlgroupaddresses
		print
		print
		# tell user about any group responders
		print "Group responders are:"
		for device in devicelist:
			if device.isgroupresponder:
				print device.address, " responds to group(s): ", device.respondgroupaddresses
		print


def searchdevicelist(devicelist, address):
	"""
	# a simple search function to find an address in the saved device list.
	:param devicelist: the devicelist to be searched
	:param address: the address i'm looking for.
	:return: if the device exists, return True and the device index in the list. otherwise, False and None.
	"""
	deviceindex = 0
	for device in devicelist:
		if device.address == address:
			return True, deviceindex
		else:
			pass
		deviceindex += 1
	return False, None


def analyzepacket(devicelist, packet):
	if packet[0] == "2" or packet[0] == "3":
		# this is an ACK message which means the direct message generated a response. capture what it means.
		# may as well get the responder and controller addresses now...
		responderaddress = packet[12:20]
		controlleraddress = packet[3:11]

		if len(devicelist) == 0:
			# no devices in the devicelist. make 2 new devices, the responder and controller, respectively.
			responder = Device(address = responderaddress, isresponder = True, respondstoaddress = controlleraddress)
			controller = Device(address = controlleraddress, iscontroller = True, controlsaddress = responderaddress)

			# add responder and controller to the device list.
			devicelist.append(responder)
			devicelist.append(controller)

		else:
			# there are already devices in the device list.
			# figure out if the responder is in the list and the devicelist index.
			responderisinlist, deviceindex = searchdevicelist(devicelist, responderaddress)
			if responderisinlist:
				devicelist[deviceindex].isresponder = True
				devicelist[deviceindex].udpaterespondsdirecttolist(controlleraddress)

			else:
				# this means the responder is not yet in the device list. create and append.
				responder = Device(address = responderaddress, isresponder = True,
				                   respondstoaddress = controlleraddress)
				devicelist.append(responder)

			# figure out if the controller is already in device list and if so, what index.
			controllerisinlist, deviceindex = searchdevicelist(devicelist, controlleraddress)
			if controllerisinlist:
				# need to make sure that the device object is identified as a controller.
				devicelist[deviceindex].iscontroller = True
				devicelist[deviceindex].updatecontrollsdirectlist(responderaddress)

			else:
				# the device was not found in the dev list, make new controller and add to the list.
				controller = Device(address = controlleraddress, iscontroller = True,
				                    controlsaddress = responderaddress)
				devicelist.append(controller)

	if packet[0] == "6" or packet[0] == "7":
		# group cleanup ACK message
		# I assume the same for extended group ACK cleanup messages. haven't seen one in the wild yet.
		responderaddress = packet[12:20]
		controlleraddress = packet[3:11]
		groupaddress = "group " + packet[24:26]
		if len(devicelist) == 0:
			# no devices in the devicelist. make 2 new devices, the responder and controller, respectively.
			responder = Device(address = responderaddress, isresponder = True, respondstoaddress = controlleraddress,
			                   isgroupresponder = True, respondstogroupaddress = groupaddress)
			controller = Device(address = controlleraddress, iscontroller = True, controlsaddress = responderaddress,
			                    isgroupcontroller = True, controllgroupaddress = groupaddress)

			# add responder and controller to the device list.
			devicelist.append(responder)
			devicelist.append(controller)
		else:
			# there are already devices in the device list.
			# figure out if the responder is in the list and the devicelist index.
			responderisinlist, deviceindex = searchdevicelist(devicelist, responderaddress)
			if responderisinlist:
				devicelist[deviceindex].isresponder = True
				devicelist[deviceindex].udpaterespondsdirecttolist(controlleraddress)
				devicelist[deviceindex].isgroupresponder = True
				devicelist[deviceindex].updaterepondtogrouplist(groupaddress)

			else:
				# this means the responder is not yet in the device list. create and append.
				responder = Device(address = responderaddress, isresponder = True,
				                   respondstoaddress = controlleraddress,
				                   isgroupresponder = True, respondstogroupaddress = groupaddress)
				devicelist.append(responder)

			# figure out if the controller is already in device list and if so, what index.
			controllerisinlist, deviceindex = searchdevicelist(devicelist, controlleraddress)
			if controllerisinlist:
				# need to make sure that the device object is identified as a controller.
				devicelist[deviceindex].iscontroller = True
				devicelist[deviceindex].updatecontrollsdirectlist(responderaddress)
				devicelist[deviceindex].isgroupcontroller = True
				devicelist[deviceindex].updatecontrolgrouplist(groupaddress)

			else:
				# make new controller and add to the list.
				controller = Device(address = controlleraddress, iscontroller = True,
				                    controlsaddress = responderaddress,
				                    isgroupcontroller = True, controllgroupaddress = groupaddress)
				devicelist.append(controller)

	elif packet[0] == "8" or packet[0] == "9":
		# this is a broadcast - we know information about the source. easy.
		address = packet[3:11]
		devcat = packet[18:20]

		if len(devicelist) == 0:
			# need to add our first item into the list.
			device = Device(address, devcat)
			devicelist.append(device)
		else:
			# find the device and devicelist index, if able.
			deviceinlist, deviceindex = searchdevicelist(devicelist, address)
			if deviceinlist:
				devicelist[deviceindex].devcatstring = devcat
				devicelist[deviceindex].devcatdescription = devicelist[deviceindex].devcatlookup(devcat)
			else:
				device = Device(address, devcat)
				devicelist.append(device)

	elif packet[0] == "C" or packet[0] == "D":
		# a group broadcast message from a device. Save that the group address is being used and the
		address = packet[3:11]
		groupaddress = "group " + packet[12:14]

		if len(devicelist) == 0:
			# need to add our first item into the list.
			device = Device(address = address, isgroupcontroller = True, controllgroupaddress = groupaddress)
			devicelist.append(device)
		else:
			deviceinlist, deviceindex = searchdevicelist(devicelist, address)
			if deviceinlist:
				devicelist[deviceindex].controlsgroup = True
				devicelist[deviceindex].updatecontrolgrouplist(groupaddress)
			else:
				device = Device(address, isgroupcontroller = True, controllgroupaddress = groupaddress)
				devicelist.append(device)


def analyzefile(inputfilename):
	inputfile = open(inputfilename, "r")
	devicelist = list()
	for line in inputfile:
		# the line is the timestamp, so the next line is the packet I care about...
		packet = next(inputfile).strip("\n")
		# go analyze said packet. need to pass the device list to keep track of that...
		analyzepacket(devicelist, packet)

	# print it!
	devicelistprint(devicelist)


def main():
	args = parseargs()
	inputfilename = args.inputfilename

	if inputfilename is None:
		print "must specify an input file name"
		sys.exit(0)

	analyzefile(inputfilename)

# run main.
if __name__ == "__main__":
	main()
	sys.exit(1)
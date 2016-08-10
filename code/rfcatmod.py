#!/usr/bin/env python
"""
@Author: mays85
@date: July 2016
@version: 1.0
@Description: This is the config function for the yardstick. I did this so I could ensure the
listener and sender were configured exactly the same for maximum spam-listening.
Use this function to create the yardsticks

Based on statistical testing using the yardstick, there is not a significant difference in the header / syncword
/ preamble information. The best results actually came when I listened on the carrier freq for everything.
~80% capture rate

"""
from rflib import *


def configure_rfcat(interface=0):
	"""
	:param interface: YardStick USB to use (first one plugged in is 0, next is 1, etc).
	:return: The configured YardStick (RfCat) device.
	"""
	# configs.
	frequency = 915000000
	brate = 9124
	bandwidth = 200000
	mdmdeviation = 75000
	# syncword = 0x662A
	# syncword = 0x6666

	# make the device.
	device = RfCat(interface)

	# configure the device.
	device.setFreq(frequency)
	device.setMdmDRate(brate)
	device.setMdmChanBW(bandwidth)
	device.setMdmDeviatn(mdmdeviation)
	device.setMdmModulation(MOD_2FSK)
	device.setMdmSyncMode(SYNCM_CARRIER)
	# device.setMdmSyncMode(SYNCM_CARRIER_15_of_16)
	# device.setMdmSyncWord(syncword)
	device.setBSLimit(BSCFG_BS_LIMIT_6)
	device.setPktPQT(0)
	device.setMaxPower()

	return device

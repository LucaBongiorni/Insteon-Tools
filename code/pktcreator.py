#!/usr/bin/env python
"""
@Author: most of the code was created by Evil Pete (Peter Shipley). minor edits by mays85
@Description: This file contains the Pkt class, which is used for parsing raw bits into lists of Pkts.
Additionally, pkt_crc function is used in the sending process.
"""

from myexceptions import InvalidManchesterEncoding


startheader_i = "0011000101010101"
startheader = "1100111010101010"
startheadermark = 5

lsfr_table = [0x00, 0x30, 0x60, 0x50,  # 0 1 2 3
			0xC0, 0xF0, 0xA0, 0x90,  # 4 5 6 7
			0x80, 0xB0, 0xE0, 0xD0,  # 8 9 A B
			0x40, 0x70, 0x20, 0x10]  # C D E F


class Pkt(object):
	def __init__(self, dat, timestp=None, offset=0) :
		"""
		reads a raw packet in the form of a string of "1' & "0"
		"""
		self.raw_dat = dat
		self.offset = dat
		self.validcrc = 0
		self.calc_crc = None
		self.timestamp = timestp
		self.dat = extract_pkt_data(self.raw_dat)

		if len(self.dat) >= 10:
			self.calc_crc = pkt_crc(self.dat)
			self.hex_str = self.pkt_simple()

	def pkt_simple(self):
		try:
			if len(self.dat) < 4 :
				return ""
			h = ["{:02X}".format(x) for x in self.dat]
			# a = [h[0], " ".join(h[1:4]), " ".join(h[4:7]),  " ".join(h[7:23])]
			a = [h[0], " ".join(h[1:4]), " ".join(h[4:7]), " ".join(h[7:23])]

			if len(h) > 22:
				# a.append(":")
				a.append(" ".join(h[23:]))

		except Exception, err:
			# pass
			print "err", err
			if self.dat:
				print "dat", self.dat
			# print "a", a
			# if h: print "h", h
				# raise

		return " ".join(a)


# ###----END OF CLASS-----#### #

def pkt_crc(dat):
	"""
	:param dat: takes an instion packet in form of a list of ints
	:return: returns the CRC for RF packet

			This uses a table lookup to effectivly doing:
			r ^= dat[i] ;
			r ^= (( r ^ ( r << 1 )) & 0x0F) << 4 ;
	"""

	# check if this is an short packet or extended packet
	if dat[0] & 0b00010000:
		crc_len = 23
	else:
		crc_len = 9

	r = 0
	for i in dat[:crc_len]:
		r ^= i
		r ^= lsfr_table[r & 0x0F]

	return r


def parse_insteon_pkt(data, timestamp):
	"""
	:param data: string of raw bytes
	:param timestamp: timestamp info for the bytes
	:return: a list of insteon pkt in the form of a list of hex strings.
	"""

	pktlist = get_pkt(data, timestamp)
	if pktlist is None:
		return None
	for p in pktlist:
		if p.calc_crc is not None:
			if p.dat[0] & 0b00010000:
				x = 23
				p.hex_str = p.hex_str[0:x * 3 + 2]
			else:
				x = 9
				p.hex_str = p.hex_str[0:x * 3 + 2]
			if x <= len(p.dat):
				if p.calc_crc == p.dat[x]:
					p.validcrc = 1
	return pktlist


def demanchester(s):
	"""
	:param s: byte in string "10011001
	:return: nibble in string "1010"
	"""
	i = 1
	b = list()
	slen = len(s)

	# Note that since 1 starts as "1"
	# we are testing the 2nd bit for '1' or '0'
	while i < slen:
		if s[i] == s[i - 1]:
			raise InvalidManchesterEncoding(s[i], s[i - 1])
		if s[i] == "1":
			b.append("1")
		else:
			b.append("0")
		i += 2
	return "".join(b)


def extract_pkt_data(dat):
	"""
	reads a raw packet in the form of a string of "1' & "0"
	returns a string parsed data in the form of an array of ints
	"""

	i = 0
	if dat[startheadermark:startheadermark+2] == "11" :
		i = startheadermark

	results = list()

	# j = 0
	dm = ''
	while dat[i:i + 2] == "11":
		i += 2
		try:
			dm = demanchester(dat[i:i + 26])
		except Exception:
			if len(results) >= 10 :
				break

		if len(dm) < 13:
			break
		i += 26
		# count_field = int(dm[4::-1], 2)
		dat_field = int(dm[:4:-1], 2)

		results.append(dat_field)

	return results


def get_pkt(dat, ts):
	""" returns list packet object """
	try:
		si = startindex = dat.find(startheader, 0)

		if startindex == -1:
			si = startindex = dat.find(startheader_i, 0)
		if si > -1:
			dat = dat.replace('0','A')
			dat = dat.replace('1','0')
			dat = dat.replace('A','1')

		if startindex == -1:
			# print "No startheader"
			return None

		header_len = len(startheader)
		data_len=len(dat)
		subpkt = list()
		pkt_list = list()

		prev_header = si
		si = dat.find(startheader, prev_header + header_len)
		while si > 0:
			subpkt.append((prev_header, si))
			prev_header = si
			si = dat.find(startheader, prev_header + header_len)
		else:
			subpkt.append((prev_header, data_len))

	except IndexError:
		print "Index Fail"
		return

	for sb in subpkt:
		try:
			pkt = Pkt(dat[sb[0]:sb[1]], ts, sb[0])
		except ValueError:
			print ["{:02X}".format(x) for x in pkt.dat]
			continue
		else:
			pkt_list.append(pkt)

	return pkt_list

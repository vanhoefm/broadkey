#include <Python.h>
#include <time.h>
#include <stdio.h>

#include "mypcap.h"


// =================================== DEFINES AND TYPES ========================================

#define FORMAT_CAP      1
#define FORMAT_IVS      2
#define FORMAT_IVS2     3

#define TCPDUMP_MAGIC           0xA1B2C3D4
#define TCPDUMP_CIGAM           0xD4C3B2A1
#define IVSONLY_MAGIC           "\xBF\xCA\x84\xD4"
#define IVS2_MAGIC              "\xAE\x78\xD1\xFF"
#define IVS2_EXTENSION		"ivs"
#define IVS2_VERSION             1

#define PCAP_VERSION_MAJOR      2
#define PCAP_VERSION_MINOR      4

#define uchar  unsigned char
#define ushort unsigned short
#define uint   unsigned int
#define ulong  unsigned long

//BSSID const. length of 6 bytes; can be together with all the other types
#define IVS2_BSSID	0x0001

//ESSID var. length; alone, or with BSSID
#define IVS2_ESSID	0x0002

//wpa structure, const. length; alone, or with BSSID
#define IVS2_WPA	0x0004

//IV+IDX+KEYSTREAM, var. length; alone or with BSSID
#define IVS2_XOR	0x0008

/* [IV+IDX][i][l][XOR_1]..[XOR_i][weight]                                                        *
 * holds i possible keystreams for the same IV with a length of l for each keystream (l max 32)  *
 * and an array "int weight[16]" at the end                                                      */
#define IVS2_PTW        0x0010

//unencrypted packet
#define IVS2_CLR        0x0020

/** Main file header */
typedef struct pcap_file_header
{
    uint magic;
    ushort version_major;
    ushort version_minor;
    int thiszone;
    uint sigfigs;
    uint snaplen;
    uint linktype;
} pcap_file_header;


typedef struct pcap_pkthdr
{
    int tv_sec;
    int tv_usec;
    uint caplen;
    uint len;
} pcap_pkthdr;

struct ivs2_filehdr
{
    unsigned short version;
};

struct ivs2_pkthdr
{
    unsigned short  flags;
    unsigned short  len;
};


// =================================== FUNCTIONS ========================================

static int pcap_write_header(FILE *fp, int linktype)
{
	pcap_file_header hdr;

	hdr.magic         = TCPDUMP_MAGIC;
	hdr.version_major = PCAP_VERSION_MAJOR;
	hdr.version_minor = PCAP_VERSION_MINOR;
	hdr.thiszone      = 0;
	hdr.sigfigs       = 0;
	hdr.snaplen       = 65535;
	hdr.linktype      = linktype;

	if (fwrite(&hdr, sizeof(hdr), 1, fp) != 1) {
		//PyErr_SetFromErrno(PyErr_SetFromErrno);
		PyErr_Format(PyExc_IOError, "Failed to write pcap header");
		return -1;
	}

	return 0;
}


int pcap_read_header(FILE *fp, pcap_file_header *hdr_out)
{
	pcap_file_header hdr;

	if (fread(&hdr, sizeof(pcap_file_header), 1, fp) != 1) {
		//PyErr_SetFromErrno(PyErr_SetFromErrno);
		PyErr_Format(PyExc_IOError, "Failed to read pcap header (file too small?)");
		return -1;
	}

	if (hdr.magic != TCPDUMP_MAGIC) {
		PyErr_Format(PyExc_ValueError, "Pcap header magic value not equal to TCPDUMP_MAGIC");
		return -1;
	}

	if (hdr_out != NULL)
		*hdr_out = hdr;	

	return 0;
}


FILE * pcap_open(const char *filename, bool writable, uint linktype)
{
	FILE *pcap;

	if (writable)
	{
		pcap = fopen(filename, "wb");
		if (pcap == NULL) {
			PyErr_Format(PyExc_IOError, "Unable to open file %s for writing", filename);
			return NULL;
		}
		if (pcap_write_header(pcap, linktype)) {
			PyErr_Format(PyExc_IOError, "Failed to write pcap header to %s", filename);
			fclose(pcap);
			return NULL;
		}
	}
	else
	{
		pcap_file_header hdr;

		pcap = fopen(filename, "rb");
		if (pcap == NULL)  {
			PyErr_Format(PyExc_IOError, "Unable to open file %s for reading", filename);
			return NULL;
		}
		if (pcap_read_header(pcap, &hdr)) {
			fclose(pcap);
			return NULL;
		}
		if (hdr.linktype != linktype) {
			PyErr_Format(PyExc_ValueError, "Pcap file %s has unexpected linktype %d", filename, hdr.linktype);
			fclose(pcap);
			return NULL;
		}
	}

	return pcap;
}


int pcap_write_packet(FILE *fp, void *buf, size_t len, uint64_t tsf)
{
	pcap_pkthdr pkthdr;

	// get system time if no TSF is given
	if (tsf == 0) {
		struct timespec now;
		clock_gettime(CLOCK_MONOTONIC, &now);

		pkthdr.tv_sec  = now.tv_sec;
		pkthdr.tv_usec = now.tv_nsec / 1000;
	} else {
		pkthdr.tv_sec  = tsf / 1000000;
		pkthdr.tv_usec = tsf % 1000000;
	}

	pkthdr.caplen  = len;
	pkthdr.len     = len;

	if (fwrite(&pkthdr, sizeof(pkthdr), 1, fp) != 1) {
		//PyErr_SetFromErrno(PyErr_SetFromErrno);
		PyErr_Format(PyExc_IOError, "Failed to write pcap packet header to file");
		return -1;
	}

	if (fwrite(buf, len, 1, fp) != 1) {
		//PyErr_SetFromErrno(PyErr_SetFromErrno);
		PyErr_Format(PyExc_IOError, "Failed to write pcap packet data to file");
		return -1;
	}

	return 0;
}


int pcap_read_packet(FILE *fp, void *buf, size_t len, uint64_t *tsf)
{
	pcap_pkthdr pkthdr;

	if (fread(&pkthdr, sizeof(pkthdr), 1, fp) != 1) {
		if (feof(fp)) return 0;

		//PyErr_SetFromErrno(PyErr_SetFromErrno);
		PyErr_Format(PyExc_IOError, "Failed to read pcap packet header");
		return -1;
	}

	if (pkthdr.caplen > len) {
		//PyErr_SetFromErrno(PyErr_SetFromErrno);
		PyErr_Format(PyExc_ValueError, "%s: buffer too small (size %lu) for packet in pcap file (size %d)",
			__FUNCTION__, len, pkthdr.caplen);
		return -1;
	}

	if (fread(buf, pkthdr.caplen, 1, fp) != 1) {
		//PyErr_SetFromErrno(PyErr_SetFromErrno);
		PyErr_Format(PyExc_IOError, "Failed to read pcap packet data");
		return -1;
	}

	if (tsf) *tsf = pkthdr.tv_sec * 1000000 + pkthdr.tv_usec;

	return pkthdr.len;
}




#ifndef broadkey_ieee80211header_h__
#define broadkey_ieee80211header_h__

#include <stdint.h>

#define PREPACK __attribute__ ((__packed__))

/** http://www.radiotap.org/ */
typedef struct PREPACK ieee80211_radiotap_header {
        uint8_t        it_version;     /* set to 0 */
        uint8_t        it_pad;
        uint16_t       it_len;         /* entire length including radiotap header */
        uint32_t       it_present;     /* fields present */
} ieee80211_radiotap_header;

#define IEEE80211_FCSLEN		4
// Minimum size of ACK
#define IEEE80211_MINSIZE		10

enum TYPE {
	TYPE_MNGMT = 0,
	TYPE_CNTRL = 1,
	TYPE_DATA  = 2
};

enum CONTROL {
	CONTROL_ACK  = 13
};

enum MNGMT {
	MNGMT_BEACON = 8
};

/** IEEE Std 802.11-2007 paragraph 7.1 MAC frame formats */
typedef struct PREPACK ieee80211header {
	/** 7.1.3.1 Frame Control Field */
	struct PREPACK fc
	{
		uint8_t version : 2;
		/** see IEEE802.11-2012 8.2.4.1.3 Type and Subtype fields */
		uint8_t type : 2;
		uint8_t subtype : 4;
		uint8_t tods : 1;
		uint8_t fromds : 1;
		uint8_t morefrag : 1;
		uint8_t retry : 1;
		uint8_t pwrmgt : 1;
		uint8_t moredata : 1;
		uint8_t protectedframe : 1;
		uint8_t order : 1;
	} fc;
	/** 7.1.3.2 Duration/ID field. Content varies with frame type and subtype. */
	uint16_t duration_id;
	/** 7.1.3.3 Address fields. For this program we always assume 3 addresses. */
	uint8_t addr1[6];
	uint8_t addr2[6];
	uint8_t addr3[6];
	/** 7.1.3.4 Sequence Control Field */
	struct PREPACK sequence
	{
		uint8_t fragnum : 4;
		uint16_t seqnum : 12;
	} sequence;
} ieee80211header;

/** 7.1.3.5 QoS Control field. This is not present in all frames, and exact
 * usage of the bits depends on the type/subtype. Here we assume QoS data frame. */
typedef struct PREPACK ieee80211qosheader {
	// 7.1.3.5.1 TID subfield. Allowed values depend on Access Policy (7.3.2.30).
	uint8_t tid : 4;
	uint8_t eosp : 1;
	uint8_t ackpolicy : 2;
	uint8_t reserved : 1;
	uint8_t appsbufferstate;
} ieee80211qosheader;

static inline bool ieee80211_broadcast_mac(uint8_t mac[6]) { return mac[0] & 0x01; }
static inline bool ieee80211_dataqos(const ieee80211header *hdr) {
	return hdr->fc.type == TYPE_DATA && hdr->fc.subtype >= 8 && hdr->fc.subtype <= 12;
}
static inline int ieee80211_hdrlen(const uint8_t *buf, int taillen = 0) {
	ieee80211header *hdr = (ieee80211header*)buf;
	int pos = sizeof(ieee80211header);
	if (hdr->fc.tods && hdr->fc.fromds)
		pos += 6;
	if (ieee80211_dataqos(hdr))
		pos += sizeof(ieee80211qosheader);
	return pos + taillen;
}

/** IEEE Std 802.11-2007 paragraph 8.3.3.2 TKIP MPDU formats */
typedef struct PREPACK tkipheader
{
	struct PREPACK iv
	{
		uint8_t tsc1;
		uint8_t wepseed;
		uint8_t tsc0;
		uint8_t reserved : 5;
		uint8_t extendediv : 1;
		uint8_t keyid : 2;
	} iv;
	struct PREPACK eiv
	{
		uint8_t tsc2;
		uint8_t tsc3;
		uint8_t tsc4;
		uint8_t tsc5;
	} eiv;
} tkipheader;

/** IEEE Std 802.11-2007 paragraph 8.3.3.2 TKIP MPDU formats */
typedef struct PREPACK tkiptail
{
	union {
		uint64_t mic;
		uint8_t micbuff[8];
	};
	uint32_t icv;
} tkiptail;

typedef struct PREPACK ccmpheader
{
	uint8_t pn0;
	uint8_t pn1;
	uint8_t reserved1;
	uint8_t reserved2 : 5;
	uint8_t extendediv : 1;
	uint8_t keyid : 2;

	uint8_t pn2;
	uint8_t pn3;
	uint8_t pn4;
	uint8_t pn5;
} ccmpheader;

static const int TIMEUNIT_USEC = 1024;

typedef struct PREPACK ieee80211fixedparams {
	// Value of the timing synchronization function (TSF)
	uint64_t timestamp;
	// Number of time units (TUs) between target beacon transmission times (TBTTs)
	uint16_t interval;
	// Capabilities (not detected yet..)
	uint16_t capabilities;
} ieee80211fixedparams;

static const uint8_t IE_TAG_VENDOR_SPECIFIC = 221;

typedef struct PREPACK ieee80211tlv {
	uint8_t tag;
	uint8_t length;
	uint8_t value[0];
} ieee80211tlv;

static inline ieee80211tlv * ieee80211_next_tlv(ieee80211tlv *tlv, size_t *tlvlen = NULL) {
	size_t iesize = sizeof(ieee80211tlv) + tlv->length;
	if (tlvlen) *tlvlen = iesize > *tlvlen ? 0 : *tlvlen - iesize;
	return (ieee80211tlv *)((uint8_t*)(tlv + 1) + tlv->length);
}

ieee80211tlv * ieee80211_search_tlv(ieee80211tlv *tlv, uint8_t tag, size_t *tlvlen);
ieee80211tlv * ieee80211_get_vendor_tlv(ieee80211tlv *tlv, const uint8_t *oui, uint8_t type, size_t tlvlen);

static inline ieee80211tlv * ieee80211_get_tlv(ieee80211tlv *tlv, uint8_t tag, size_t tlvlen)
{
	return ieee80211_search_tlv(tlv, tag, &tlvlen);
}

/** Hexdump of a complete 802.11 frame */
void dump_wlan_packet(const unsigned char* h80211, int len);

#endif // broadkey_ieee80211header_h__

#include <Python.h>
#include <stdint.h>

#include "ieee80211header.h"

ieee80211tlv * ieee80211_search_tlv(ieee80211tlv *tlv, uint8_t tag, size_t *tlvlen)
{
	if (*tlvlen < sizeof(ieee80211tlv))
		return NULL;

	while (*tlvlen >= sizeof(ieee80211tlv))
	{
		if (sizeof(ieee80211tlv) + tlv->length  > *tlvlen) {
			//PySys_WriteStdout("Warning: advertised Information Element length (%d) larger than possible (%d)\n",
			//	tlv->length, *tlvlen);
			return NULL;
		}

		if (tlv->tag == tag)
			return tlv;
		
		tlv = ieee80211_next_tlv(tlv, tlvlen);
	}

	return NULL;
}

ieee80211tlv * ieee80211_get_vendor_tlv(ieee80211tlv *tlv, const uint8_t *oui, uint8_t type, size_t tlvlen)
{
	while (NULL != (tlv = ieee80211_search_tlv(tlv, IE_TAG_VENDOR_SPECIFIC, &tlvlen)))
	{
		if (memcmp(tlv->value, oui, 3) == 0 && tlv->value[3] == type)
			return tlv;

		tlv = ieee80211_next_tlv(tlv, &tlvlen);
	}

	return NULL;
}


void dump_wlan_packet(const unsigned char* h80211, int len)
{
	int z, i, j;
	int mi_b = 0, mi_s = 0, mi_d = 0, mi_t = 0, mi_r = 0, is_wds = 0, key_index_offset;

	z = ((h80211[1] & 3) != 3) ? 24 : 30;
	if ((h80211[0] & 0x80) == 0x80) /* QoS */
		z += 2;

	switch (h80211[1] & 3) {
	case 0:
		mi_b = 16;
		mi_s = 10;
		mi_d = 4;
		is_wds = 0;
		break;
	case 1:
		mi_b = 4;
		mi_s = 10;
		mi_d = 16;
		is_wds = 0;
		break;
	case 2:
		mi_b = 10;
		mi_s = 16;
		mi_d = 4;
		is_wds = 0;
		break;
	case 3:
		mi_t = 10;
		mi_r = 4;
		mi_d = 16;
		mi_s = 24;
		is_wds = 1;
		break; // WDS packet
	}

	PySys_WriteStdout("\n\n  Size: %d, FromDS: %d, ToDS: %d", len, (h80211[1] & 2) >> 1, (h80211[1] & 1));

	if ((h80211[0] & 0x0C) == 8 && (h80211[1] & 0x40) != 0) {
		//             if (is_wds) key_index_offset = 33; // WDS packets have an additional MAC, so the key index is at byte 33
		//             else key_index_offset = 27;
		key_index_offset = z + 3;

		if ((h80211[key_index_offset] & 0x20) == 0)
			PySys_WriteStdout(" (WEP)");
		else
			PySys_WriteStdout(" (WPA)");
	}

	PySys_WriteStdout("\n\n");

	if (is_wds) {
		PySys_WriteStdout("  Transmitter  =  %02X:%02X:%02X:%02X:%02X:%02X\n",
				h80211[mi_t], h80211[mi_t + 1], h80211[mi_t + 2],
				h80211[mi_t + 3], h80211[mi_t + 4], h80211[mi_t + 5]);

		PySys_WriteStdout("     Receiver  =  %02X:%02X:%02X:%02X:%02X:%02X\n",
				h80211[mi_r], h80211[mi_r + 1], h80211[mi_r + 2],
				h80211[mi_r + 3], h80211[mi_r + 4], h80211[mi_r + 5]);
	} else {
		PySys_WriteStdout("        BSSID  =  %02X:%02X:%02X:%02X:%02X:%02X\n",
				h80211[mi_b], h80211[mi_b + 1], h80211[mi_b + 2],
				h80211[mi_b + 3], h80211[mi_b + 4], h80211[mi_b + 5]);
	}

	PySys_WriteStdout("    Dest. MAC  =  %02X:%02X:%02X:%02X:%02X:%02X\n",
			h80211[mi_d], h80211[mi_d + 1], h80211[mi_d + 2], h80211[mi_d
					+ 3], h80211[mi_d + 4], h80211[mi_d + 5]);

	PySys_WriteStdout("   Source MAC  =  %02X:%02X:%02X:%02X:%02X:%02X\n",
			h80211[mi_s], h80211[mi_s + 1], h80211[mi_s + 2], h80211[mi_s
					+ 3], h80211[mi_s + 4], h80211[mi_s + 5]);

	/* print a hex dump of the packet */

	for (i = 0; i < len; i++) {
		if ((i & 15) == 0) {
			if (i == 224) {
				PySys_WriteStdout("\n  --- CUT ---");
				break;
			}

			PySys_WriteStdout("\n  0x%04x: ", i);
		}

		PySys_WriteStdout("%02x", h80211[i]);

		if ((i & 1) != 0)
			PySys_WriteStdout(" ");

		if (i == len - 1 && ((i + 1) & 15) != 0) {
			for (j = ((i + 1) & 15); j < 16; j++) {
				PySys_WriteStdout("  ");
				if ((j & 1) != 0)
					PySys_WriteStdout(" ");
			}

			PySys_WriteStdout(" ");

			for (j = 16 - ((i + 1) & 15); j < 16; j++)
				PySys_WriteStdout("%c", (h80211[i - 15 + j] < 32 || h80211[i - 15 + j]
						> 126) ? '.' : h80211[i - 15 + j]);
		}

		if (i > 0 && ((i + 1) & 15) == 0) {
			PySys_WriteStdout(" ");

			for (j = 0; j < 16; j++)
				PySys_WriteStdout("%c", (h80211[i - 15 + j] < 32 || h80211[i - 15 + j]
						> 127) ? '.' : h80211[i - 15 + j]);
		}
	}

	PySys_WriteStdout("\n\n");
}




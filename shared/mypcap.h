/*
 * FIXME: Use real pcap library instead?
 *
 *  Copyright (C) 2001-2004  Christophe Devine
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 
 */
#ifndef broadkey_ng_pcap_h__
#define broadkey_ng_pcap_h__

#include <stdio.h>
#include <stdint.h>

#define LINKTYPE_ETHERNET       1
#define LINKTYPE_IEEE802_11     105
#define LINKTYPE_PRISM_HEADER   119
#define LINKTYPE_RADIOTAP_HDR   127
#define LINKTYPE_PPI_HDR	192


/**
 * @param writable	If true we are creating a file, otherwise we are reading a file.
 * @param linktype	If writable is true, this created a pcap file of the given type.
 *			If writable is false, linktype must match that of the file (or NULL is returned).
 */
FILE * pcap_open(const char *filename, bool writable, uint32_t linktype = LINKTYPE_RADIOTAP_HDR);

int pcap_write_packet(FILE *fp, void *buf, size_t len, uint64_t tsf);
int pcap_read_packet(FILE *fp, void *buf, size_t len, uint64_t *tsf);


#endif // broadkey_ng_pcap_h__

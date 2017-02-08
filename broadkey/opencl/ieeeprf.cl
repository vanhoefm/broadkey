/*
 * This software is Copyright (c) 2016 Mathy Vanhoef and it is hereby released
 * to the general public under the following terms: Redistribution and use in
 * source and binary forms, with or without modification, are permitted.
 *
 * This code was at one point based on wpapsk_kernel.cl of JTR-Jumbo.
 */

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_sha1.h"
#include "util.cl"

// Note that SHA-1 uses big endian 32-bit words, so we already put these words in big endian
__constant uint lblGroupKeyExp[5] = { 0x47726F75, 0x70206B65, 0x79206578, 0x70616E73, 0x696F6E00 };	    // Label "Group key expansion\0"
__constant uint lblInitCounter[4] = { 0x496E6974, 0x20436F75, 0x6E746572, 0x00000000 };                 // Label "Init Counter\0\0\0\0"


/**
 * @param data		44-byte data in Little Endian
 * @param ret		32-byte hash in Big Endian
 *
 * HMAC uses the opad and ipad.
 * SHA-1 uses the '1' bit terminator after message, and includes message lengh (ml).
 */
inline void prf256_counter(uint __private *data, uint __private *ret)
{
	uint ipad1[5] = {0xc9f7bd57, 0x621bd73b, 0xea0fead1, 0x41a5a132, 0x4e4f361d},   // Result of sha1_single(key XOR ipad)
		ipad2[5] = {0xc9f7bd57, 0x621bd73b, 0xea0fead1, 0x41a5a132, 0x4e4f361d};
	uint opad1[5] = {0x978a24a4, 0x70daf4d3, 0x13e1be88, 0x387c2231, 0x7456516dL},  // Result of sha1_single(key XOR opad)
		opad2[5] = {0x978a24a4, 0x70daf4d3, 0x13e1be88, 0x387c2231, 0x7456516dL};
	uint W1[16] = {0x496E6974, 0x20436F75, 0x6E746572, 0x00000000};                 // Label "Init Counter\0\0\0\0";
	uint W2[16];
	uint A, B, C, D, E, temp;
	uint i;

	//
	// Step 1 -- Inner hash: h = H((K' XOR ipad) || m)
	//

	/* Precalculated ipad - key would be XORed with this but has no effect since it's all zeros */

	/* Add first block of data to be HMAC'ed */
	W1[3] = *data >> 8;		 // fill in remaining 3 bytes
	W1[4] = *data++ << 24;	 // fill in first 1 byte
	#pragma unroll
	for (i = 4; i < 14; i++) {
		W1[i] = (W1[i] & 0xff000000) | *data >> 8;		// fill in remaining 3 bytes
		W1[i + 1] = *data++ << 24;						// fill in first 1 byte
	}
	W1[14] |= 0x008000;	     // counter in PRF + SHA1 bit '1' to end message
	W1[15] = 0x0;            // not enough space to put 64-bit message length (ml)

	COPY_BLOCK(W2, W1);
	W2[14] |= 0x010000;      // increase counter in PRF data

	sha1_block(W1, ipad1);
	sha1_block(W2, ipad2);


	/* SHA1 padding and message length in bits: padding + message length (ipad + label + counter + data) */
	SET_BLOCK(W1, 0);
	W1[15] = (64 + 13 + 1 + 44) << 3;

	COPY_BLOCK(W2, W1);
	sha1_block(W1, ipad1);   // update(digest) + final
	sha1_block(W2, ipad2);   // update(digest) + final


	//
	// Step 2 -- Outer hash: H((K' XOR opad) || h)
	//

	/* opad - key would be XORed with this but has no effect since it's all zeros */

	/* take inner hash and update SHA1 digest with it */
	COPY_PAD(W1, ipad1);
	W1[5] = 0x80000000;
	W1[15] = (64 + 20) << 3;
	sha1_block_160Z(W1, opad1); // update(digest) + final

	/* take inner hash and update SHA1 digest with it */
	COPY_PAD(W2, ipad2);
	W2[5] = 0x80000000;
	W2[15] = (64 + 20) << 3;
	sha1_block_160Z(W2, opad2); // update(digest) + final


	//
	// Step 3 - Return PRF output
	//

	COPY_PAD(ret, opad1);
	ret[5] = opad2[0];
	ret[6] = opad2[1];
	ret[7] = opad2[2];
}


/**
 * Note: The return GTK is in Big Endian. So to test 7D E2 F6 73 6B 43 64 41 ..
 *       use 0x7de2f673 and 0x6b436441.
 *
 * @param gmk		32-byte group master key in Big Endian
 * @param data		36-byte data (AA || gnonce) in Big Endian
 * @param ret		32-byte hash
 *
 * HMAC uses the opad and ipad.
 * SHA-1 uses the '1' bit terminator after message, and includes message lengh (ml).
 */
inline void prf256_gtk(uint __private *gmk, uint __private *data, uint __private *ret)
{
	uint W1[16], W2[16];
	uint ipad1[5], ipad2[5];
	uint opad1[5], opad2[5];
	uint A, B, C, D, E, temp;
	uint i;

	//
	// Step 1 -- Inner hash: h = H((K' XOR ipad) || m)
	//

	/* Calculate ipad */
	#pragma unroll
	for (i = 0; i < 8; i++)
		W1[i] = 0x36363636 ^ gmk[i];
	#pragma unroll
	for (i = 8; i < 16; i++)
		W1[i] = 0x36363636;
	sha1_single(W1, ipad1);         // update(ipad)
	COPY_PAD(ipad2, ipad1);

	/* Add first block of data to be HMAC'ed */
	#pragma unroll
	for (i = 0; i < 5; i++)
		W1[i] = lblGroupKeyExp[i];
	#pragma unroll
	for (i = 0; i < 9; i++)
		W1[5 + i] = data[i];
	W1[14] = (data[9] & 0xFFFF0000) | 0x80;    // last two bytes + counter in PRF + SHA1 bit '1' to end message + padding
	W1[15] = 0;

	COPY_BLOCK(W2, W1);
	W2[14] |= 0x0100;               // increase counter in PRF data

	sha1_block(W1, ipad1);          // update(data)
	sha1_block(W2, ipad2);          // update(data)

	/* SHA1 padding and message length in bits: padding + message length (ipad + label + data + prf-counter) */
	SET_BLOCK(W1, 0);
	W1[15] = (64 + 20 + 38 + 1) << 3;

	COPY_BLOCK(W2, W1);
	sha1_block(W1, ipad1);          // update(digest) + final
	sha1_block(W2, ipad2);          // update(digest) + final


	//
	// Step 2 -- Outer hash: H((K' XOR opad) || h)
	//

	/* opad - key would be XORed with this but has no effect since it's all zeros */

	#pragma unroll
	for (i = 0; i < 8; i++)
		W1[i] = 0x5c5c5c5c ^ gmk[i];
	#pragma unroll
	for (i = 8; i < 16; i++)
		W1[i] = 0x5c5c5c5c;
	sha1_single(W1, opad1);         // update(opad)
	COPY_PAD(opad2, opad1);


	/* take inner hash and update SHA1 digest with it */
	COPY_PAD(W1, ipad1);
	W1[5] = 0x80000000;
	W1[15] = (64 + 20) << 3;
	sha1_block_160Z(W1, opad1); // update(digest) + final

	/* take inner hash and update SHA1 digest with it */
	COPY_PAD(W1, ipad2);
	W1[5] = 0x80000000;
	W1[15] = (64 + 20) << 3;
	sha1_block_160Z(W1, opad2); // update(digest) + final


	//
	// Step 3 - Return PRF output
	//

	COPY_PAD(ret, opad1);
	ret[5] = opad2[0];
	ret[6] = opad2[1];
	ret[7] = opad2[2];
}



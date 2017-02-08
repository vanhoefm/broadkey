/*
 * MD5 OpenCL kernel based on Solar Designer's MD5 algorithm implementation at:
 * http://openwall.info/wiki/people/solar/software/public-domain-source-code/md5
 *
 * This software is Copyright (c) 2010, Dhiru Kholia <dhiru.kholia at gmail.com>
 * and Copyright (c) 2012, magnum
 * and Copyright (c) 2015, Sayantan Datta <std2048@gmail.com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * Useful References:
 * 1. CUDA MD5 Hashing Experiments, http://majuric.org/software/cudamd5/
 * 2. oclcrack, http://sghctoma.extra.hu/index.php?p=entry&id=11
 * 3. http://people.eku.edu/styere/Encrypt/JS-MD5.html
 * 4. http://en.wikipedia.org/wiki/MD5#Algorithm
 */

#define AMD_PUTCHAR_NOCAST
#include "opencl_misc.h"


/* The basic MD5 functions */
#ifdef USE_BITSELECT
#define F(x, y, z)	bitselect((z), (y), (x))
#define G(x, y, z)	bitselect((y), (x), (z))
#else
#if HAVE_ANDNOT
#define F(x, y, z) ((x & y) ^ ((~x) & z))
#else
#define F(x, y, z) (z ^ (x & (y ^ z)))
#endif
#define G(x, y, z)	((y) ^ ((z) & ((x) ^ (y))))
#endif
#define H(x, y, z)	(((x) ^ (y)) ^ (z))
#define H2(x, y, z)	((x) ^ ((y) ^ (z)))
#define I(x, y, z)	((y) ^ ((x) | ~(z)))

/* The MD5 transformation for all four rounds. */
#define STEP(f, a, b, c, d, x, t, s)	  \
	(a) += f((b), (c), (d)) + (x) + (t); \
	    (a) = rotate((a), (uint)(s)); \
	    (a) += (b)

inline void md5_hash(__private uint *hash, __private uint *W)
{
	/* Hash values A, B, C, D */
	hash[0] = 0x67452301;
	hash[1] = 0xefcdab89;
	hash[2] = 0x98badcfe;
	hash[3] = 0x10325476;

	/* Round 1 */
	STEP(F, hash[0], hash[1], hash[2], hash[3], W[0], 0xd76aa478, 7);
	STEP(F, hash[3], hash[0], hash[1], hash[2], W[1], 0xe8c7b756, 12);
	STEP(F, hash[2], hash[3], hash[0], hash[1], W[2], 0x242070db, 17);
	STEP(F, hash[1], hash[2], hash[3], hash[0], W[3], 0xc1bdceee, 22);
	STEP(F, hash[0], hash[1], hash[2], hash[3], W[4], 0xf57c0faf, 7);
	STEP(F, hash[3], hash[0], hash[1], hash[2], W[5], 0x4787c62a, 12);
	STEP(F, hash[2], hash[3], hash[0], hash[1], W[6], 0xa8304613, 17);
	STEP(F, hash[1], hash[2], hash[3], hash[0], W[7], 0xfd469501, 22);
	STEP(F, hash[0], hash[1], hash[2], hash[3], W[8], 0x698098d8, 7);
	STEP(F, hash[3], hash[0], hash[1], hash[2], W[9], 0x8b44f7af, 12);
	STEP(F, hash[2], hash[3], hash[0], hash[1], W[10], 0xffff5bb1, 17);
	STEP(F, hash[1], hash[2], hash[3], hash[0], W[11], 0x895cd7be, 22);
	STEP(F, hash[0], hash[1], hash[2], hash[3], W[12], 0x6b901122, 7);
	STEP(F, hash[3], hash[0], hash[1], hash[2], W[13], 0xfd987193, 12);
	STEP(F, hash[2], hash[3], hash[0], hash[1], W[14], 0xa679438e, 17);
	STEP(F, hash[1], hash[2], hash[3], hash[0], W[15], 0x49b40821, 22);

	/* Round 2 */
	STEP(G, hash[0], hash[1], hash[2], hash[3], W[1], 0xf61e2562, 5);
	STEP(G, hash[3], hash[0], hash[1], hash[2], W[6], 0xc040b340, 9);
	STEP(G, hash[2], hash[3], hash[0], hash[1], W[11], 0x265e5a51, 14);
	STEP(G, hash[1], hash[2], hash[3], hash[0], W[0], 0xe9b6c7aa, 20);
	STEP(G, hash[0], hash[1], hash[2], hash[3], W[5], 0xd62f105d, 5);
	STEP(G, hash[3], hash[0], hash[1], hash[2], W[10], 0x02441453, 9);
	STEP(G, hash[2], hash[3], hash[0], hash[1], W[15], 0xd8a1e681, 14);
	STEP(G, hash[1], hash[2], hash[3], hash[0], W[4], 0xe7d3fbc8, 20);
	STEP(G, hash[0], hash[1], hash[2], hash[3], W[9], 0x21e1cde6, 5);
	STEP(G, hash[3], hash[0], hash[1], hash[2], W[14], 0xc33707d6, 9);
	STEP(G, hash[2], hash[3], hash[0], hash[1], W[3], 0xf4d50d87, 14);
	STEP(G, hash[1], hash[2], hash[3], hash[0], W[8], 0x455a14ed, 20);
	STEP(G, hash[0], hash[1], hash[2], hash[3], W[13], 0xa9e3e905, 5);
	STEP(G, hash[3], hash[0], hash[1], hash[2], W[2], 0xfcefa3f8, 9);
	STEP(G, hash[2], hash[3], hash[0], hash[1], W[7], 0x676f02d9, 14);
	STEP(G, hash[1], hash[2], hash[3], hash[0], W[12], 0x8d2a4c8a, 20);

	/* Round 3 */
	STEP(H, hash[0], hash[1], hash[2], hash[3], W[5], 0xfffa3942, 4);
	STEP(H2, hash[3], hash[0], hash[1], hash[2], W[8], 0x8771f681, 11);
	STEP(H, hash[2], hash[3], hash[0], hash[1], W[11], 0x6d9d6122, 16);
	STEP(H2, hash[1], hash[2], hash[3], hash[0], W[14], 0xfde5380c, 23);
	STEP(H, hash[0], hash[1], hash[2], hash[3], W[1], 0xa4beea44, 4);
	STEP(H2, hash[3], hash[0], hash[1], hash[2], W[4], 0x4bdecfa9, 11);
	STEP(H, hash[2], hash[3], hash[0], hash[1], W[7], 0xf6bb4b60, 16);
	STEP(H2, hash[1], hash[2], hash[3], hash[0], W[10], 0xbebfbc70, 23);
	STEP(H, hash[0], hash[1], hash[2], hash[3], W[13], 0x289b7ec6, 4);
	STEP(H2, hash[3], hash[0], hash[1], hash[2], W[0], 0xeaa127fa, 11);
	STEP(H, hash[2], hash[3], hash[0], hash[1], W[3], 0xd4ef3085, 16);
	STEP(H2, hash[1], hash[2], hash[3], hash[0], W[6], 0x04881d05, 23);
	STEP(H, hash[0], hash[1], hash[2], hash[3], W[9], 0xd9d4d039, 4);
	STEP(H2, hash[3], hash[0], hash[1], hash[2], W[12], 0xe6db99e5, 11);
	STEP(H, hash[2], hash[3], hash[0], hash[1], W[15], 0x1fa27cf8, 16);
	STEP(H2, hash[1], hash[2], hash[3], hash[0], W[2], 0xc4ac5665, 23);

	/* Round 4 */
	STEP(I, hash[0], hash[1], hash[2], hash[3], W[0], 0xf4292244, 6);
	STEP(I, hash[3], hash[0], hash[1], hash[2], W[7], 0x432aff97, 10);
	STEP(I, hash[2], hash[3], hash[0], hash[1], W[14], 0xab9423a7, 15);
	STEP(I, hash[1], hash[2], hash[3], hash[0], W[5], 0xfc93a039, 21);
	STEP(I, hash[0], hash[1], hash[2], hash[3], W[12], 0x655b59c3, 6);
	STEP(I, hash[3], hash[0], hash[1], hash[2], W[3], 0x8f0ccc92, 10);
	STEP(I, hash[2], hash[3], hash[0], hash[1], W[10], 0xffeff47d, 15);
	STEP(I, hash[1], hash[2], hash[3], hash[0], W[1], 0x85845dd1, 21);
	STEP(I, hash[0], hash[1], hash[2], hash[3], W[8], 0x6fa87e4f, 6);
	STEP(I, hash[3], hash[0], hash[1], hash[2], W[15], 0xfe2ce6e0, 10);
	STEP(I, hash[2], hash[3], hash[0], hash[1], W[6], 0xa3014314, 15);
	STEP(I, hash[1], hash[2], hash[3], hash[0], W[13], 0x4e0811a1, 21);
	STEP(I, hash[0], hash[1], hash[2], hash[3], W[4], 0xf7537e82, 6);
	STEP(I, hash[3], hash[0], hash[1], hash[2], W[11], 0xbd3af235, 10);
	STEP(I, hash[2], hash[3], hash[0], hash[1], W[2], 0x2ad7d2bb, 15);
	STEP(I, hash[1], hash[2], hash[3], hash[0], W[9], 0xeb86d391, 21);

	hash[0] += 0x67452301;
	hash[1] += 0xefcdab89;
	hash[2] += 0x98badcfe;
	hash[3] += 0x10325476;
}



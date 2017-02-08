#include <Python.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include <openssl/md5.h>

#include "crypto.h"
#include "util.h"
#include "broadcom.h"

/** We assume the router is using 32-bit "long int" variables */
struct hashbuff_t
{
	struct {
		uint32_t tv_sec;
		uint32_t tv_usec;
	} tv;
	struct {
		uint32_t tz_minuteswest;
		uint32_t tz_dsttime;
	} tz;
};


static void get_hash_data(struct hashbuff_t *hashbuff)
{
	struct timeval tv;
	struct timezone tz;

	gettimeofday(&tv, &tz);

	hashbuff->tv.tv_sec = tv.tv_sec;
	hashbuff->tv.tv_usec = tv.tv_usec;
	hashbuff->tz.tz_minuteswest = tz.tz_minuteswest;
	hashbuff->tz.tz_dsttime = tz.tz_dsttime;

	// Broadcom's NAS application does not call rand somewhere else, and also
	// does not call srand. Hence this output is predictable.
	int randval = rand();

	PySys_WriteStdout("randval 0x%08X | tv.sec 0x%08X tv.usec 0x%08X | tz.minwest 0x%08X tz.dsttime 0x%08X\n",
		randval, hashbuff->tv.tv_sec, hashbuff->tv.tv_usec, hashbuff->tz.tz_minuteswest, hashbuff->tz.tz_dsttime);

	hashbuff->tv.tv_sec ^= randval;
}


void nas_rand128(uint8_t *rand128)
{
	hashbuff_t hashbuff;
	MD5_CTX md5;

	get_hash_data(&hashbuff);
	pydump_buffer((uint8_t*)&hashbuff, sizeof(hashbuff), "hashbuff");

	MD5_Init(&md5);
	MD5_Update(&md5, (unsigned char *) &hashbuff.tv, sizeof(hashbuff.tv));
	MD5_Update(&md5, (unsigned char *) &hashbuff.tz, sizeof(hashbuff.tz));
	MD5_Final(rand128, &md5);
}


void generate_gmk(uint8_t gmk[32])
{
	nas_rand128(&gmk[0]);
	PySys_WriteStdout("\n");
	nas_rand128(&gmk[16]);
}


PyObject * py_bcom_test_crypto(PyObject *self, PyObject *args)
{
	unsigned char prefix[] = "Group key expansion";
	uint8_t gnonce[32] = {}; /** Leaked through public key_counter */
	uint8_t gmk[32];
	uint8_t gtk[32];
	uint8_t data[6 + 32];

	// Initialize fake GNONCE to test algorithms
	for (int i = 0; i < 32; ++i)
		gnonce[i] = i;

	generate_gmk(gmk);
	pydump_buffer(gmk, sizeof(gmk), "Generated GMK");

	pydump_buffer(gnonce, sizeof(gnonce), "Used GNONCE");

	memcpy(data    , "\x01\x02\x03\x04\x05\x06", 6);
	memcpy(data + 6, gnonce, 32);
	ieee80211_prf_256(gmk, sizeof(gmk), prefix, strlen((char *)prefix), data, sizeof(data), gtk);

	pydump_buffer(gtk, sizeof(gtk), "Generated GTK");

	Py_RETURN_NONE;
}


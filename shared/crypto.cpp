#include <string.h>

#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "crypto.h"

/**
 * @param key, key_len			key material for HMAC
 * @param label, label_len		identifying label
 * @param data, data_len		seed of the PRF
 * @param output, output_len	output of the PRF
 *
 * See 802.11-2012: 11.6.1.2 "PRF".
 */
void ieee80211_prf(
	uint8_t *key, size_t key_len,
	uint8_t *label, size_t label_len,
	uint8_t *data, size_t data_len,
	uint8_t *output, size_t output_len)
{
	size_t	i, total_len, outpos;
	unsigned int outlen;
    uint8_t	input[1024];
	
	/* input = label || 0 || data */
	memcpy(input, label, label_len);
	input[label_len] = 0;
	memcpy(&input[label_len + 1], data, data_len);
	total_len =	label_len + 1 + data_len;

	/* reserve space for the loop counter i */
	total_len++;

	/* generate the output in blocks */
	outpos = 0;
	for	(i = 0;	i <	output_len / SHA_DIGEST_LENGTH; i++) {
		input[total_len - 1] = i;

		outlen = SHA_DIGEST_LENGTH;
		HMAC(EVP_sha1(), key, key_len, input, total_len, &output[outpos], &outlen);
		outpos += SHA_DIGEST_LENGTH;
	}

	/* handle last part with intermediate copy to temp buffer */
	if (output_len % SHA_DIGEST_LENGTH) {
		uint8_t temp[SHA_DIGEST_LENGTH];

		input[total_len - 1] = i;
		outlen = SHA_DIGEST_LENGTH;
		HMAC(EVP_sha1(), key, key_len, input, total_len, temp, &outlen);

		memcpy(&output[outpos], temp, output_len % SHA_DIGEST_LENGTH);
	}
}


/**
 * @param key, key_len			key material for HMAC
 * @param label, label_len		identifying label
 * @param data, data_len		seed of the PRF
 * @param output, output_len	output of the PRF
 *
 * See 802.11-2012: 11.6.1.2 "PRF".
 */
void ieee80211_prf_256(
	uint8_t *key, size_t key_len,
	uint8_t *label, size_t label_len,
	uint8_t *data, size_t data_len,
	uint8_t *output)
{
	size_t total_len;
	unsigned int outlen;
	uint8_t input[1024];

	/* input = label || 0 || data */
	memcpy(input, label, label_len);
	input[label_len] = 0;
	memcpy(&input[label_len + 1], data, data_len);
	total_len =	label_len + 1 + data_len;

	/* reserve space for the loop counter i */
	total_len++;

	/* generate the output in blocks */
	input[total_len - 1] = 0;
	outlen = SHA_DIGEST_LENGTH;
	HMAC(EVP_sha1(), key, key_len, input, total_len, &output[0], &outlen);

	/* handle last part with intermediate copy to temp buffer */
	uint8_t temp[SHA_DIGEST_LENGTH];

	input[total_len - 1] = 1;
	outlen = SHA_DIGEST_LENGTH;
	HMAC(EVP_sha1(), key, key_len, input, total_len, temp, &outlen);

	memcpy(&output[20], temp, 12);
}


#ifndef broadkey_crypto_h_
#define broadkey_crypto_h_

#include <stdint.h>

enum EncType {
	EncType_Unknown,
	EncType_TKIP,
	EncType_CCMP
};

/** extend random material */
void ieee80211_prf(
	uint8_t *key, size_t key_len,
	uint8_t *label, size_t label_len,
	uint8_t *data, size_t data_len,
	uint8_t *output, size_t output_len);

void ieee80211_prf_256(
	uint8_t *key, size_t key_len,
	uint8_t *label, size_t label_len,
	uint8_t *data, size_t data_len,
	uint8_t *output);

#endif // broadkey_crypto_h_

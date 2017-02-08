#ifndef broadkey_crc_h_
#define broadkey_crc_h_

#include <stdint.h>

uint32_t calc_crc(void *buf, size_t len);

/** len includes the crc */
bool endswith_valid_crc(void *buf, size_t len);
/** len doesn't include space for crc */
void append_crc(void *buf, size_t len);

#endif // broadkey_crc_h_

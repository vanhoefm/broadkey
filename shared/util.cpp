#include <Python.h>
#include <stdint.h>

#include "util.h"

void pydump_buffer(const uint8_t *buf, size_t len, const char *prefix /*= NULL*/)
{
	char ascii[17] = {0};
	size_t i = 0;

	if (prefix) PySys_WriteStdout("%s:\n\t", prefix);
	else PySys_WriteStdout("\t");

	for (i = 0; i < len; ++i) {
		if (i > 0 && i % 16 == 0) {
			PySys_WriteStdout("  %s\n\t", ascii);
		} else if (i > 0 && i % 8 == 0) {
			PySys_WriteStdout(" ");
		}

		PySys_WriteStdout("%02X ", buf[i]);

		ascii[i % 16] = buf[i];
		if (!isprint(buf[i])) ascii[i % 16] = '.';
	}
	
	int padding = (i % 16) == 0 ? 0 : 3 * (16 - (i % 16)) + ((i %16) < 8);
	PySys_WriteStdout("%*s  %s\n", padding, "", ascii);
}


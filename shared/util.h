#ifndef broadkey_util_h_
#define broadkey_util_h_

#include <stdint.h>

#define METHOD_ENTRY(name, doc) \
	{#name,         py_##name,        METH_VARARGS, doc}

void pydump_buffer(const uint8_t *buf, size_t len, const char *prefix = NULL);

#endif // broadkey_util_h_

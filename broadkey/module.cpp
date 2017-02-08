#include <Python.h>
#include <stdint.h>

#define PY_ARRAY_UNIQUE_SYMBOL biases_ARRAY_API
#include <numpy/arrayobject.h>

#include "util.h"
#include "ralink.h"
#include "broadcom.h"

// ================================ PYTHON BINDINGS ================================ 

static PyMethodDef modmethods[] = {
	// Attacks against Ralink / MediaTek
	METHOD_ENTRY(rl_test_crypto, "Unit tests of our crypto algorithms"),

	METHOD_ENTRY(rl_get_ssids, "Get a list of attackable SSIDs"),
	METHOD_ENTRY(rl_extract_hash, "Extract hash from a pcap capture"),
	METHOD_ENTRY(rl_generate_keys, "Generate list of possible keys (GMKs or GNONCEs)"),

	// Attack against Broadcom
	METHOD_ENTRY(bcom_test_crypto, "Unit tests of our crypto algorithms"),

	// For the demo
	METHOD_ENTRY(dump_packet, "Dump the decrypted packet"),

	{NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC initbroadkey(void)
{
	import_array();

	/** init C functions */
	Py_InitModule("broadkey", modmethods);
}



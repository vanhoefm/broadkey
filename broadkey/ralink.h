#ifndef broadkey_ralink_h__
#define broadkey_ralink_h__

PyObject * py_rl_test_crypto(PyObject *self, PyObject *args);

PyObject * py_rl_get_ssids(PyObject *self, PyObject *args);
PyObject * py_rl_extract_hash(PyObject *self, PyObject *args);
PyObject * py_rl_generate_keys(PyObject *self, PyObject *args);

PyObject * py_dump_packet(PyObject *self, PyObject *args);

#endif // broadkey_ralink_h__

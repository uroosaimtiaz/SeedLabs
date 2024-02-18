#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "hexify_dehexify.h"
#include <stdio.h>

/*
    This code was adapted from the Python C API documentation
    https://docs.python.org/3/extending/embedding.html
    Section 1.3
    Changes made to reflect known argument number and types
    as well as conditional error handling and decref calls
*/
int dehexify(const char *script, const char *function, const char *hex_str, char **ascii_out) {
    PyObject *pName, *pModule, *pFunc;
    PyObject *pArgs, *pValue;

    pName = PyUnicode_DecodeFSDefault(script);

    pModule = PyImport_Import(pName);
    Py_DECREF(pName);

    if (pModule != NULL) {
        pFunc = PyObject_GetAttrString(pModule, function);

        if (pFunc && PyCallable_Check(pFunc)) {
            pArgs = PyTuple_New(1);
            pValue = PyUnicode_FromString(hex_str);

            if (!pValue) {
                Py_DECREF(pArgs);
                Py_DECREF(pModule);
                fprintf(stderr, "Cannot convert hex string\n");
                return 1;
            }
            PyTuple_SetItem(pArgs, 0, pValue);

            pValue = PyObject_CallObject(pFunc, pArgs);
            Py_DECREF(pArgs);

            if (pValue != NULL) {
                if (PyUnicode_Check(pValue)) {
                    const char *result = PyUnicode_AsUTF8(pValue);
                    *ascii_out = strdup(result); // Allocate and copy the result string
                    if (!*ascii_out) { // strdup failed
                        fprintf(stderr, "Failed to allocate memory for ascii_out\n");
                        Py_DECREF(pValue);
                        return 1;
                    }
                }
                Py_DECREF(pValue);
            } else {
                Py_DECREF(pFunc);
                Py_DECREF(pModule);
                PyErr_Print();
                fprintf(stderr, "Call failed\n");
                return 1;
            }
            Py_DECREF(pFunc);
        } else {
            if (PyErr_Occurred())
                PyErr_Print();
            fprintf(stderr, "Cannot find function \"%s\"\n", function);
        }
        Py_DECREF(pModule);
    } else {
        PyErr_Print();
        fprintf(stderr, "Failed to load \"%s\"\n", script);
        return 1;
    }
    return 0;
}

/*
    This code was adapted from the Python C API documentation
    https://docs.python.org/3/extending/embedding.html
    Section 1.3
    Changes made to reflect known argument number and types
    as well as conditional error handling and decref calls
*/
int hexify(const char *script, const char *function, const char *ascii_str, BIGNUM *m) {
    PyObject *pName, *pModule, *pFunc;
    PyObject *pArgs, *pValue;

    pName = PyUnicode_DecodeFSDefault(script);

    pModule = PyImport_Import(pName);
    Py_DECREF(pName);

    if (pModule != NULL) {
        pFunc = PyObject_GetAttrString(pModule, function);

        if (pFunc && PyCallable_Check(pFunc)) {
            pArgs = PyTuple_New(1);
            pValue = PyUnicode_FromString(ascii_str);

            if (!pValue) {
                Py_DECREF(pArgs);
                Py_DECREF(pModule);
                fprintf(stderr, "Cannot convert message to bytes\n");
                return 1;
            }
            PyTuple_SetItem(pArgs, 0, pValue);

            pValue = PyObject_CallObject(pFunc, pArgs);
            Py_DECREF(pArgs);

            if (pValue != NULL) {
                const char *hex_str = PyUnicode_AsUTF8(pValue);
                BN_hex2bn(&m, hex_str);
                Py_DECREF(pValue);
            } 
            else {
                Py_DECREF(pFunc);
                Py_DECREF(pModule);
                PyErr_Print();
                fprintf(stderr, "Call failed\n");
                return 1;
            }
            Py_DECREF(pFunc);
        } else {
            if (PyErr_Occurred())
                PyErr_Print();
            fprintf(stderr, "Cannot find function \"%s\"\n", function);
        }
        Py_DECREF(pModule);
    } else {
        PyErr_Print();
        fprintf(stderr, "Failed to load \"%s\"\n", script);
        return 1;
    }
    return 0;
}
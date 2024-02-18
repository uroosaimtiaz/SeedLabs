#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "hexify_dehexify.h"
#include <stdio.h>
#include <openssl/bn.h>
/*
    3.3
*/

void printBN(char *msg, BIGNUM *a)
{
    char *number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main(int argc, char *argv[])
{
    Py_Initialize();

    // Get the current working directory
    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        // Convert current directory to Python object
        PyObject *sysPath = PySys_GetObject("path");
        PyObject *path = PyUnicode_FromString(cwd);
        // Append current directory to sys.path
        PyList_Append(sysPath, path);
        Py_DECREF(path);
    } else {
        perror("getcwd() error");
        return 1;
    }
    /*  
        Expected input: ./program d n y
        d is the private key, n is the modulus, y is the encrypted message (in hex)
        Example usage:
        cd path/to/current/directory
        gcc -o decrypt decrypt_message.c hexify_dehexify.c $(python3-config --cflags) -L/usr/lib -lpython3.10 $(python3-config --ldflags) -lssl -lcrypto -ldl
        ./decrypt $(./priv_key 0x879a5ee58ade33942040f  0x3bef5e448f18ae4ff08c65 0x10001 4) 0x0182c38e75c5a4889ec3c8da3602114b42e1d2cc9e58
    */

    if (argc != 4) {
        fprintf(stderr, "Usage: %s d n y\n", argv[0]);
        return 1;
    }

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *x = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *y = BN_new();

    BN_hex2bn(&d, argv[1] + 2); // d = argv[1], ignore the 0x
    BN_hex2bn(&n, argv[2] + 2); // n = argv[2]
    BN_hex2bn(&y, argv[3] + 2); // y = argv[3]

    BN_mod_exp(x, y, d, n, ctx); // x = y^d mod n
    printBN("x = ", x); // Print the decrypted message in hex

    char *ascii_out = malloc(256);  // Allocate memory for the output string
    if (ascii_out == NULL) {
        fprintf(stderr, "Failed to allocate memory\n");
        Py_Finalize();
        return 1;
    }

    char *hex_str = BN_bn2hex(x);
    if (dehexify("hex_ascii", "hex_to_ascii", hex_str, &ascii_out) != 0) {
        fprintf(stderr, "Failed to dehexify message\n");
        free(ascii_out);  // Free the memory if dehexify fails
        Py_Finalize();
        return 1;
    }

    printf("Decrypted message: %s\n", ascii_out); // Print the decrypted message in ASCII

    // Free memory
    free(ascii_out);
    BN_CTX_free(ctx);
    BN_free(x);
    BN_free(n);
    BN_free(y);
    Py_Finalize();
    return 0;
}
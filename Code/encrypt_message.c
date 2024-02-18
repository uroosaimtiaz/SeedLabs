#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "hexify_dehexify.h"
#include <stdio.h>
#include <openssl/bn.h>
/*
    3.2
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
        Expected input: ./program x n e
        x is the message in ASCII format
        p and q are the primes used to generate n in hex
        e is the public exponent in hex
        Example usage:
        cd path/to/current/directory
        gcc -o encrypt encrypt_message.c hexify_dehexify.c $(python3-config --cflags) -L/usr/lib -lpython3.10 $(python3-config --ldflags) -lssl -lcrypto -ldl
        ./encrypt 'i<3crypto' $(./priv_key 0x879a5ee58ade33942040f  0x3bef5e448f18ae4ff08c65 0x10001 2) 0x10001
    */

    if (argc != 4) {
        fprintf(stderr, "Usage: %s x n e\n", argv[0]);
        Py_Finalize();
        return 1;
    }

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *x = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *y = BN_new();

    char *x_str = argv[1]; // x = argv[1]
    BN_hex2bn(&n, argv[2] + 2); // n = argv[2] ignore the 0x
    BN_hex2bn(&e, argv[3] + 2); // e = argv[3] ignore the 0x

    /*  
        The hexify function will call the python script to convert the message to hex
        and then store it in Bignum x
        parameters: script = "hex_ascii.py", function = "ascii_to_hex", message = x_str, m = x
    */
    if (hexify("hex_ascii", "ascii_to_hex", x_str, x) != 0) {
        fprintf(stderr, "Failed to hexify message\n");
        Py_Finalize();
        return 1;
    }

    if (BN_cmp(x, n) >= 0)
    {
        printf("x is greater than or equal to n\n");
        Py_Finalize();
        return 1;
    }

    BN_mod_exp(y, x, e, n, ctx); // y = x^e mod n
    printBN("y = ", y); // Print the encrypted message

    // Free memory
    BN_CTX_free(ctx);
    BN_free(x);
    BN_free(n);
    BN_free(e);
    BN_free(y);
    Py_Finalize();
    return 0;
}
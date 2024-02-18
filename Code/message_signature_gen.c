#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "hexify_dehexify.h"
#include <stdio.h>
#include <openssl/bn.h>
/*
    3.4
*/

void printBN(BIGNUM *a)
{
    char *number_str = BN_bn2hex(a); // binary to hex
    printf("0x%s", number_str);
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
        Expected input: ./program d n x
        d is the private key in hex
        n is the modulus in hex
        x is the message in ascii
        Example usage:
        cd path/to/current/directory
        gcc -o sign message_signature_gen.c hexify_dehexify.c $(python3-config --cflags) -L/usr/lib -lpython3.10 $(python3-config --ldflags) -lssl -lcrypto -ldl
        ./sign $(./priv_key 0x879a5ee58ade33942040f  0x3bef5e448f18ae4ff08c65 0x10001 4) 'I owe you $100'
    */

    if (argc != 4) {
        fprintf(stderr, "Usage: %s d n x\n", argv[0]);
        Py_Finalize();
        return 1;
    }

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *d = BN_new(); // private key
    BIGNUM *n = BN_new(); // modulus
    BIGNUM *x = BN_new(); // message
    BIGNUM *s = BN_new(); // signature

    BN_hex2bn(&d, argv[1] + 2);
    BN_hex2bn(&n, argv[2] + 2);
    char *x_str = argv[3];

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

    BN_mod_exp(s, x, d, n, ctx); // s = x^d mod n
    printBN(s); // Print the signature in hex
    printf("\n");

    BN_CTX_free(ctx);
    BN_free(d);
    BN_free(n);
    BN_free(x);
    BN_free(s);
    Py_Finalize();
    return 0;
}
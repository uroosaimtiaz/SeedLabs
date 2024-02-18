#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "hexify_dehexify.h"
#include <stdio.h>

void printBN(BIGNUM *a)
{
    char *number_str = BN_bn2hex(a); // binary to hex
    printf("0x%s", number_str);
    OPENSSL_free(number_str);
}

void flip_bitBN(BIGNUM *a, int bit) { 
    // if you wanted to flip the 5th bit, you would call flip_bitBN(a, 4)
    // or run the code again etc.
    BN_is_bit_set(a, bit) ? BN_clear_bit(a, bit) : BN_set_bit(a, bit);
}

int verify(BIGNUM *x, BIGNUM *s, BIGNUM *e, BIGNUM *n)
{
    // take the signature and apply modular exponentiation
    // and compare that to the message
    BIGNUM *result = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    BN_mod_exp(result, s, e, n, ctx); // result = s^e mod n

    int comparison = BN_cmp(result, x);

    // Free memory
    BN_CTX_free(ctx);
    BN_free(result);

    return comparison == 0;
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
        Expected input: ./program x s e n
        x: message, s: signature, e: public key, n: modulus
        Example usage:
        cd a2
        gcc -o verify verify_signature.c hexify_dehexify.c $(python3-config --cflags) -L/usr/lib -lpython3.10 $(python3-config --ldflags) -lssl -lcrypto -ldl
        ./verify 'Launch a missile.'  0x643d6f34902d9c7ec90cb0b2bca36c47fa37165c0005cab026c0542cbdb6802f  0x010001  0xae1cd4dc432798d933779fbd46c6e1247f0cf1233595113aa51b450f18116115
        ./verify 'Launch a missile.'  0x643d6f34902d9c7ec90cb0b2bca36c47fa37165c0005cab026c0542cbdb6803f  0x010001  0xae1cd4dc432798d933779fbd46c6e1247f0cf1233595113aa51b450f18116115
    */
    if (argc != 5)
    {
        printf("Usage: %s x s e n\n", argv[0]);
        return 1;
    }

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *x = BN_new();
    BIGNUM *s = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();

    char *x_str = argv[1];
    BN_hex2bn(&s, argv[2]+2); // s = argv[2] + 2 to skip the 0x
    BN_hex2bn(&e, argv[3]+2); // e = argv[3] + 2
    BN_hex2bn(&n, argv[4]+2); // n = argv[4] + 2

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

    verify(x, s, e, n) ? printf("True\n") : printf("False\n");
    // Free memory
    BN_CTX_free(ctx);
    BN_free(x);
    BN_free(s);
    BN_free(e);
    BN_free(n);
    Py_Finalize();
    return 0;
}
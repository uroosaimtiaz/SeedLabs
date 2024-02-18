#ifndef HEXIFY_DEHEXIFY_H
#define HEXIFY_DEHEXIFY_H
#include <openssl/bn.h>

// Function to convert a hexadecimal string to ASCII
int dehexify(const char *script, const char *function, const char *hex_str, char **ascii_str);

// Function to convert an ASCII string to hexadecimal
int hexify(const char *script, const char *function, const char *ascii_str, BIGNUM *m);

#endif // HEXIFY_DEHEXIFY_H
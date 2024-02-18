#include <stdio.h>
#include <openssl/bn.h>
/*
    3.4
*/

void printBN(char *msg, BIGNUM *a)
{
    char *number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main(int argc, char *argv[])
{
    /*
    The sign message 
    
    
    */

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *x = BN_new(); // message
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *s = BN_new(); // signed message

    BN_hex2bn(&p, "879a5ee58ade33942040f");
    BN_hex2bn(&q, "3bef5e448f18ae4ff08c65");
    BN_mul(n, p, q, ctx); // n = p * q

    BN_hex2bn(&x, "49206f776520796f752024323030"); // x = 'I owe you $100'
    BN_hex2bn(&d, "01A87C31CA14E9E34D1CD5B8816A148E3ACD85243B09");

    if (BN_cmp(x, n) >= 0)
    {
        printf("x is greater than or equal to n\n");
        return 1;
    }

    BN_mod_exp(s, x, d, n, ctx); // y = x^e mod n
    printBN("s = ", s);
    return 0;
}
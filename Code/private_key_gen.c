#include <stdio.h>
#include <openssl/bn.h>

void printBN(BIGNUM *a)
{
    char *number_str = BN_bn2hex(a); // binary to hex
    printf("0x%s", number_str);
    OPENSSL_free(number_str);
}

int main(int argc, char *argv[])
{
    /*
        Expected input: ./program p q e mode
        p and q are prime numbers and e is the public exponent in hex

        mode 1: print d
        mode 2: print n
        mode 3: print d, n and the number of bits in n
        mode 4: print d and n

        Example usage:
        cd a2
        gcc -o priv_key private_key_gen.c -lssl -lcrypto -ldl -I/usr/include/python3.10
        ./priv_key 0x879a5ee58ade33942040f  0x3bef5e448f18ae4ff08c65 0x10001 1
        ./priv_key 0x879a5ee58ade33942040f  0x3bef5e448f18ae4ff08c65 0x10001 2
        ./priv_key 0x879a5ee58ade33942040f  0x3bef5e448f18ae4ff08c65 0x10001 3
        ./priv_key 0x879a5ee58ade33942040f  0x3bef5e448f18ae4ff08c65 0x10001 4
    */
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <p> <q> <e> mode\n", argv[0]);
        return 1;
    }

    // Variables
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = BN_new(); // primes
    BIGNUM *q = BN_new();
    BIGNUM *e = BN_new(); // public and private exponents
    BIGNUM *d = BN_new(); 
    BIGNUM *n = BN_new(); // n and phi(n)
    BIGNUM *phi_n = BN_new(); 

    BN_hex2bn(&p, argv[1] + 2); // p = argv[1], ignore the '0x' prefix
    BN_hex2bn(&q, argv[2] + 2); // q = argv[2]
    BN_hex2bn(&e, argv[3] + 2); // e = argv[3]
    int mode = atoi(argv[4]);

    BN_mul(n, p, q, ctx); // n = p * q

    BN_sub(p, p, BN_value_one()); // p = p - 1
    BN_sub(q, q, BN_value_one()); // q = q - 1
    BN_mul(phi_n, p , q, ctx); // phi(n) = (p - 1) * (q - 1)
    BN_mod_inverse(d, e, phi_n, ctx); // d = e^-1 mod phi(n)
    
    if (mode == 1){
        printBN(d);
        printf("\n");
    }
    else if (mode == 2) {
        printBN(n);
        printf("\n");
    }
    else if (mode == 3) {
        printf("d: ");
        printBN(d);
        printf("\nn: ");
        printBN(n);
        printf("\nbits in n : %d bits\n", BN_num_bits(n));
    }
    else {
        printBN(d);
        printf(" ");
        printBN(n);
        printf("\n");
    }
    
    // Clean up
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(q);
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(phi_n);
    return 0;
}
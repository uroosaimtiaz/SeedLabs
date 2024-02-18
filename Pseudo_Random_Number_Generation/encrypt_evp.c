/*
    Use the following command to compile the code:
    gcc -o encrypt-evp encrypt_evp.c -lssl -lcrypto

    Use the following command to run the code:
    ./encrypt-evp

    The code is based on the example provided by OpenSSL:
    https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
*/

#include <stdio.h>
#include <stdlib.h>
#include <time.h> // For time_t

/* 
    Headers from example provided by OpenSSL
*/
#include <openssl/conf.h>
#include <openssl/evp.h> 
#include <openssl/err.h>
#include <string.h> // For memcmp

#define KEYSIZE 16 // 128 bits

/*
    Helper function to print errors
    provided by OpenSSL example
*/
void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

/*
    Function to encrypt provided by OpenSSL example
    Modified to use AES-128-CBC instead of AES-256-CBC
*/
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */

    /* Modified from the original example to use AES-128-CBC instead of AES-256-CBC */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

/*  
    Generate a 128 bit pseudorandom key with the given seed
    and store it in the array key which is a pointer
*/
void generate_key(time_t seed, unsigned char *key) {
    srand(seed); // Seed the random number generator
    for (int i = 0; i < KEYSIZE; i++) { // Generate a random byte 16 times
        key[i] = rand() % 256; // Store the random byte in the key array
    }
}

/*
    Main function
    Adapted from the example provided by OpenSSL
*/
int main (void)
{
    /* A 128 bit IV */
    unsigned char iv[] = { 0x6f, 0x6d, 0x65, 0x67, 0x61, 0x6c, 0x75, 0x6c, 
                            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
                        };

    /* A 128 bit plaintext to be encrypted*/
    unsigned char plaintext[] = {0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x35,
                                0x0a, 0x25, 0xbf, 0xf7, 0xa2, 0xfe, 0x0a, 0x33
                                };

    /* Loop through all possible seeds */
    for (time_t t = 1705320529; t <= 1705421329; t++) {
        unsigned char key[KEYSIZE]; // Array to store the key
        generate_key(t, key); // Generate the key

        /*
        * Buffer for ciphertext. Ensure the buffer is long enough for the
        * ciphertext which may be longer than the plaintext, depending on the
        * algorithm and mode.
        */
        unsigned char ciphertext[128]; //

        int ciphertext_len;

        /* Encrypt the plaintext */
        ciphertext_len = encrypt (plaintext, KEYSIZE, key, iv,
                                ciphertext);

        /* The original ciphertext */
        unsigned char original_ciphertext[] = {  0x40, 0x6e, 0xd6, 0xd5, 0xeb, 0xa1, 0x2a, 0x69,
                                                0xea, 0x7b, 0x69, 0xbf, 0x1e, 0xe0, 0x5b, 0x8f};

        /* Check if the encrypted plaintext matches the ciphertext */
        if (memcmp(ciphertext, original_ciphertext, 16) == 0) {
            printf("Seed: %ld\n", t); // Print the seed
            printf("Key found: "); // Print the key
            for (int i = 0; i < KEYSIZE; i++) { 
                printf("%.2x", key[i]);
            }
            printf("\n");
            return 0;
        }
    }
}
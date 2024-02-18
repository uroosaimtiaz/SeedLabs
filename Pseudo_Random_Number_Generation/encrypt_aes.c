/*
    Use the following command to compile the code:
    gcc -o encrypt-aes encrypt_aes.c -lcrypto

    Use the following command to run the code:
    ./encrypt-aes

    Documentation for AES_encrypt:
    https://man.openbsd.org/AES_encrypt.3
*/

#include <stdio.h>
#include <stdlib.h>
#include <time.h> // For time_t
#include <openssl/aes.h> // For AES encryption
#include <string.h> // For memcmp

#define KEYSIZE 16 // 128 bits

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
    XOR the plaintext with the IV and store the result
    in the plaintext array which is a pointer
*/
void initialization_vector(unsigned char *plaintext) {
    unsigned char iv[KEYSIZE] = {0x6f, 0x6d, 0x65, 0x67, 0x61, 0x6c, 0x75, 0x6c,
                                 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};

    // XORing the key with the IV
    for (int i = 0; i < KEYSIZE; i++) { // Iterate through the plaintext and IV
        plaintext[i] ^= iv[i]; // XOR a byte of the plaintext with the IV and store the result in the plaintext array
    }
}

/* 
    Encrypt the plaintext using the key and store the result
    in the cipher array which is a pointer
*/
void encrypt(unsigned char *key, unsigned char *cipher) {
    unsigned char plaintext[KEYSIZE] = {0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x35,
                                        0x0a, 0x25, 0xbf, 0xf7, 0xa2, 0xfe, 0x0a, 0x33};

    initialization_vector(plaintext); // XOR the plaintext with the IV
    AES_KEY aes_key; // declare AES_KEY variable for encryption
    AES_set_encrypt_key(key, 128, &aes_key); // prepare the key for encryption
    AES_encrypt(plaintext, cipher, &aes_key); // Encrypt the plaintext using the key and store the result in the cipher array
}

/*
    Main function
    1. Iterate through the time range
    2. Generate a key for each seed in the time range by calling the generate_key function
    3. Encrypt the plaintext using the key by calling the encrypt function
    4. Compare the encrypted plaintext with the known ciphertext
    5. If the encrypted plaintext matches the known ciphertext
        - Print the seed
        - Print the key
        - Break the loop
*/
int main() {
    time_t start_time = 1705320529; // lower bound of the time range
    time_t end_time = 1705421329;  // upper bound of the time range
    unsigned char key[KEYSIZE]; // Declare a 128 bit array to store the key
    unsigned char cipher[KEYSIZE]; // Declare a 128 bit array to store the encrypted plaintext by every key
    unsigned char ciphertext[KEYSIZE] = {0x40, 0x6e, 0xd6, 0xd5, 0xeb, 0xa1, 0x2a, 0x69,
                                        0xea, 0x7b, 0x69, 0xbf, 0x1e, 0xe0, 0x5b, 0x8f}; // Known ciphertext

    for (time_t t = start_time; t <= end_time; t++) { // Iterate through the time range
        generate_key(t, key); // Generate key for each seed
        encrypt(key, cipher); // Encrypt the plaintext using the key
        if (memcmp(cipher, ciphertext, KEYSIZE) == 0) { // Compare the encrypted plaintext with the known ciphertext
            printf("Seed: %lld\n", (long long) t); // Print the seed
            printf("Key: "); // Print the key
            for (int i = 0; i < KEYSIZE; i++) {
                printf("%.2x", key[i]);
            }
            printf("\n");
            break; // Break the loop if the key is found
        }
    }
}
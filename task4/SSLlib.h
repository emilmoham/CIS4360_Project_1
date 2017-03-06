#ifndef SSHLIB_H
#define SSHLIB_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#endif

//This is our library for all of our supporting functions for task 4.

void handleErrors(){
	//Prints any errors encountered while encrypting a string and ends EVP functions.
        ERR_print_errors_fp(stderr);
	EVP_cleanup();
	ERR_free_strings();
        abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext){
	/*
	*  This function encrypts a string using aes_128_cbc cipher mode
	*  ARGS:
	*  'plaintext' is the string one wishes to encrypt
	*  'plaintext_len' is the length of plaintext
	*  'key' is the 128-bit key to use for encrypting and decrypting the string
	*  'iv' is the initialization vector
	*  'ciphertext' is the address where the encrypted text will be stored in persistent memory
	*
	*  returns the length of the ciphertext on sucess
	*/
        EVP_CIPHER_CTX *ctx;
        int len;
        int ciphertext_len;

        // Create and initialise the context 
        if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

        // Initialise the encryption operation
        if(!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
                handleErrors();

        // Provide the message to be encrypted, and obtain the encrypted output
        if(!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
                handleErrors();
        ciphertext_len = len;

        // Finalise the encryption
        if(!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
                handleErrors();

        ciphertext_len += len;

        // Clean up
        EVP_CIPHER_CTX_free(ctx);

        return ciphertext_len;
}

void store_cipher_as_hex(char *str, int len, FILE *fp){
	/* 
	*  This function outputs the hexadecimal value of a cipher string to a given file
	*  ARGS:
	*  'str' is the ciphertext string that one wishes to store as a hexadecimal string
	*  'len' is the length of the ciphertext string, this may be unesscesary to have as an argument.
	*  'fp' is a file pointer to the file the string should be written to.
	*/
	int i;
	char c;
	for(i = 0; i < len; i++){
		c = str[i];
		fprintf(fp, "%02x", c & 0xff);
	}
	fprintf(fp, "\n");
}

char *strip_and_pad_key(char *normal){
	/*
	* This funciton removes the newline character at the end of a key read from a file and pads the key to 128 bytes
	* ARGS:
	* 'normal' is the raw line read from the dictionary of possible keys
	*
	* returns the address of a malloc'd string that can be used as a string. 
	*/
	char *stripped;
	int i;
	if((stripped = malloc(sizeof(char)*129)) == NULL){
		printf("Error allocating space for stripped string...\n");
		return NULL;
	}

	for(i = 0; normal[i]  != '\n'; i++){
		stripped[i] = normal[i];
	}
	for(; i < 128; i++){
		stripped[i] = 0x20;
	}
	stripped[128] = '\0';

	free(normal);
	return stripped;
}

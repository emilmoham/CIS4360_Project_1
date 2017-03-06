#include "SSLlib.h"

int compute_ciphers(unsigned char*, unsigned char*, char*, char*);
char *search_ciphers(unsigned char*, char*, char*);

int main(int argc, char **argv){
	char *key;
	compute_ciphers("This is a top secret.", 0x0, "words.txt", "computed_hashes.txt");
	key = search_ciphers("8d20e5056a8d24d0462ce74e4904c1b513e10d1df4a2ef2ad4540fae1ca0aaf9\n", "computed_hashes.txt", "words.txt");
	fprintf(stdout, "The key used to encrypt them message was: %s\n", key);
	free(key);
	return 0;
}

int compute_ciphers(unsigned char *plaintext, unsigned char *iv, char *dictionary_filename, char *output_filename){
	/*
	*  This function computes ciphers for a large amount of keys.
	*  ARGS:
	*  'plaintext' the plaintext you wish to encrypt
	*  'iv' the initialization vector you wish to use
	*  'dictionary_filename' the name of the textfile with the list of common english words
	*  'output_filename' the name of the file you wish to store the ciphers in
	*
	*  returns 1 on success.
	*/
	FILE *input, *output;
	int ciphertext_len;
	unsigned char ciphertext[128];
	unsigned char *key_buffer;
	size_t key_buffer_size = 128;
	
	if((input = fopen(dictionary_filename, "r")) == NULL){
		printf("Error: Unable to find \n");
		return -1;
	}
	if((output = fopen(output_filename, "w")) == NULL){
		printf("Error creating output file\n");
		return -2;
	}
	if((key_buffer = malloc(sizeof(char)*key_buffer_size)) == NULL){
		printf("Error allocating space for buffer");
		return -3;
	}

	//SSL initialization
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	//Go through the dictionary line by line
	//strip and pad each key entry to 128 bytes
	//Compute the cipher for that particular key
	//Store the cipher in an output file
	while(getline((char**)&key_buffer, &key_buffer_size, input) != -1){
		key_buffer = strip_and_pad_key(key_buffer);
		ciphertext_len = encrypt(plaintext, strlen((char*)plaintext), key_buffer, iv, ciphertext);
		store_cipher_as_hex(ciphertext, ciphertext_len, output);
	}

	//Cleanup
	fclose(input);
	fclose(output);
	free(key_buffer);
	EVP_cleanup();
	ERR_free_strings();
	return 1;
}

char *search_ciphers(unsigned char *target_cipher, char *computed_hashes_filename, char *dictionary_filename){
	/*
	*  This function searches a list of ciphers and matches a known ciphertext with it's key
	*  ARGS:
 	*  'target_cipher' the ciphertext you wish to find the key for
	*	NOTE: A newline character should be appeneded to the end of the known cipher
	*  'computed_hashes_filename' name of the file with all the computed ciphers
	*  'dictionary_filename' the name of the file with corresponding keys for the hash file.
	*
	*  returns the plaintext key as a string on success.
	*/
	FILE *computed_hashes, *key_dictionary;
	unsigned char *ciphertext;
	size_t cipher_len = 65;
	unsigned char *key_buffer;
	size_t key_buffer_len = 128;
	
	if((computed_hashes = fopen(computed_hashes_filename, "r")) == NULL){
		fprintf(stderr, "Error: Could not find precomputed hashes.\n");
		return NULL;
	}
	if((key_dictionary = fopen(dictionary_filename, "r")) == NULL){
		fprintf(stderr, "Error: Could not find common key's file\n");
		return NULL;
	}
	if((ciphertext = malloc(sizeof(char)*cipher_len)) == NULL){
		fprintf(stderr, "Error: Could not allocate space for computed hash lines\n");
		return NULL;
	}
	if((key_buffer = malloc(sizeof(char)*key_buffer_len)) == NULL){
		fprintf(stderr, "Error: could not allocate space for key storage\n");
		return NULL;	
	}

	//Go through both files 1 line at a time
	//Compare the target_cipher with the cipher we just read
	//Break if the ciphers match
	while(getline((char**)&ciphertext, &cipher_len, computed_hashes) != -1
	  && getline((char**)&key_buffer, &key_buffer_len, key_dictionary) != -1){
		if(strcmp(ciphertext, target_cipher) == 0){
			break;
		}
	}

	return key_buffer;
}

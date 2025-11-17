#include <stdio.h>
#include "encryption.h"

int main(void) {
	const uint_fast8_t input[] = "test";
	const uint_fast8_t add_data[] = "feeling proud indian army";

	uint_fast8_t *ciphertext = calloc(1024, 1); // big enough buffer
	uint_fast8_t *plaintext  = calloc(1024, 1);
	uint_fast8_t key_gen_key[32];
	uint_fast8_t nonce[12];
	memset(key_gen_key, 6, sizeof(key_gen_key));
	memset(nonce, 7, sizeof(nonce));

	size_t ciphertext_len;

	// ENCRYPT
	if (encrypt_sym(key_gen_key, nonce,
				input, sizeof(input)-1,
				add_data, sizeof(add_data)-1,
				ciphertext, &ciphertext_len))
	{
		printf("encrypt failed\n");
		return -2;
	}

	// DECRYPT
	if (decrypt_sym(key_gen_key, nonce,
				ciphertext, ciphertext_len,
				add_data, sizeof(add_data)-1,
				plaintext))
	{
		printf("decrypt failed\n");
		return -3;
	}

	printf("Decrypted: %.*s\n", (int)(ciphertext_len - 16), plaintext);

	free(ciphertext);
	free(plaintext);
	return 0;
}


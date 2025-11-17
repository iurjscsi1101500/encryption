#ifndef DEFINES_H
#define DEFINES_H

#include <stdint.h>
#include <string.h>
#include <openssl/aes.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

struct group {
	uint_fast8_t message_auth_key[16];
	uint_fast8_t message_encryption_key[32];
};

void derive_keys(const uint_fast8_t key_generating_key[32],
		const uint_fast8_t nonce[12],
		struct group *ptr)
{
	uint_fast8_t block[16], out[16];	
	AES_KEY aes_key;

	AES_set_encrypt_key(key_generating_key, 256, &aes_key);
	memcpy(block + 4, nonce, 12);

	*(uint_fast32_t*)block = 0;
	AES_encrypt(block, out, &aes_key);
	memcpy(ptr->message_auth_key, out, 8);

	*(uint_fast32_t*)block = 1;
	AES_encrypt(block, out, &aes_key);
	memcpy(ptr->message_auth_key + 8, out, 8);

	*(uint_fast32_t*)block = 2;
	AES_encrypt(block, out, &aes_key);
	memcpy(ptr->message_encryption_key, out, 8);

	*(uint_fast32_t*)block = 3;
	AES_encrypt(block, out, &aes_key);
	memcpy(ptr->message_encryption_key + 8, out, 8);

	*(uint_fast32_t*)block = 4;
	AES_encrypt(block, out, &aes_key);
	memcpy(ptr->message_encryption_key + 16, out, 8);

	*(uint_fast32_t*)block = 5;
	AES_encrypt(block, out, &aes_key);
	memcpy(ptr->message_encryption_key + 24, out, 8);
}
// openssl already provides AES_CTR (but its absolute dogshit, so i am gonna create my own)
void aes_ctr(const uint_fast8_t key[32], const uint_fast8_t tag[16], const uint_fast8_t *input, size_t input_sz, uint_fast8_t *output)
{
	AES_KEY aes_key;
	AES_set_encrypt_key(key, 256, &aes_key);

	uint_fast8_t counter_block[16];
	memcpy(counter_block, tag, 16);
	counter_block[15] |= 0x80;

	uint_fast32_t *counter = (uint_fast32_t*)counter_block;
	size_t i;
	uint_fast8_t keystream[16];

	while (input_sz >= 16) {
		AES_encrypt(counter_block, keystream, &aes_key);
		(*counter)++;
		for (i = 0; i < 16; i++)
			output[i] = input[i] ^ keystream[i];

		input += 16;
		output += 16;
		input_sz -= 16;
	}

	if (input_sz > 0) {
		AES_encrypt(counter_block, keystream, &aes_key);
		(*counter)++;
		for (i = 0; i < input_sz; i++)
			output[i] = input[i] ^ keystream[i];
	}
}

int encrypt_sym(const uint_fast8_t key_generating_key[32], const uint_fast8_t nonce[12],
	const size_t nonce_size, const uint_fast8_t *input, const size_t input_size,
	const uint_fast8_t *add_data, uint_fast8_t output)
{
	if (sizeof(input) > 0x1000000000 || sizeof(add_data) > 0x1000000000 || sizeof(input) <= 0 || sizeof(add_data) <= 0)
		return -1;

	struct group keys;
	derive_keys(key_generating_key, nonce, &keys);

	return 0;
}
#endif

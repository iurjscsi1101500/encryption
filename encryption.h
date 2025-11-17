#ifndef DEFINES_H
#define DEFINES_H

#include <stdint.h>
#include <string.h>
#include <openssl/aes.h>

struct group {
	uint_fast8_t message_auth_key[16];
	uint_fast8_t message_encryption_key[32];
};

void derive_keys(const uint_fast8_t key_generating_key[32],
		const uint_fast8_t nonce[12],
		struct group *ptr)
{
	uint_fast32_t counter, i;
	uint_fast8_t block[16], out[16];	
	AES_KEY aes_key;
	AES_set_encrypt_key(key_generating_key, 256, &aes_key);
	for (counter = 0; counter <= 5; counter++) {
		memset(block, 0, 16);
		//this will break on BE system (but who uses them anyways)
		*(uint_fast32_t*)block = counter;

		memcpy(block + 4, nonce, 12);
		AES_encrypt(block, out, &aes_key);

		if (counter <= 1) {
			for (i = 0; i < 8; i++) {
				ptr->message_auth_key[counter * 8 + i] = out[i];
			}
		} else {
			for (i = 0; i < 8; i++) {
				ptr->message_encryption_key[counter * 8 + i] = out[i];
			}
		}
	}
}
// openssl already provides AES_CTR (but its absolute dogshit, so i am gonna create my own)

void AES_CTR(uint_fast8_t *out, const uint_fast8_t *in, const uint_fast8_t key[32],
	uint_fast8_t counter_block[16])
{
	AES_KEY aes_key;
	AES_set_encrypt_key(key, 256, &aes_key);

	uint_fast8_t keystream[16];
	size_t processed = 0, block_size, i;
	uint_fast32_t counter;
	while (processed < sizeof(in)) {
		AES_encrypt(counter_block, keystream, &aes_key);
		*(uint_fast32_t*)counter_block += 1;

		block_size = (sizeof(in) - processed > 16) ? 16 : (sizeof(in) - processed);
		for (i = 0; i < block_size; i++)
			out[processed + i] = in[processed + i] ^ keystream[i];

		processed+=block_size;
	}
}
#endif

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

void AES_CTR(uint_fast8_t *out, uint_fast8_t *in, const size_t len, const uint_fast8_t key[32],
	const uint_fast8_t init_counter_block[16])
{
	AES_KEY aes_key;
	uint_fast8_t block[16];
	uint_fast8_t keystream_block[16];
	uint_fast32_t ok;
	size_t i, out_len = 0, local_len = len;
	uint_fast8_t *local_in = in;

	memcpy(block, init_counter_block, 16);
	AES_set_encrypt_key(key, 256, &aes_key);	
	while(local_len > 0) {
		AES_encrypt(block, keystream_block, &aes_key);
		*(uint_fast32_t *)block += 1;
		ok = MIN(local_len, sizeof(keystream_block));

		for (i = 0; i < ok; i++)
			out[out_len++] = keystream_block[i] ^ local_in[i];

		local_in += ok;
		local_len -= ok;
	}

}
#endif

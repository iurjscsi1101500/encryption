#ifndef DEFINES_H
#define DEFINES_H

#include <stdint.h>
#include <string.h>
#include <openssl/aes.h>

struct group {
	uint_fast8_t message_auth_key[16];
	uint_fast8_t message_encryption_key[32];
};

static inline void derive_keys(const AES_KEY aes_key,
		const uint_fast8_t nonce[12],
		struct group *ptr)
{
	uint_fast8_t block[16], out[16];	
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
static inline void AES_CTR(const AES_KEY aes_key, const uint_fast8_t tag[16], const uint_fast8_t *input, size_t input_size, uint_fast8_t *output)
{
	uint_fast8_t counter_block[16];
	memcpy(counter_block, tag, 16);
	counter_block[15] |= 0x80;

	uint_fast32_t *counter = (uint_fast32_t*)counter_block;
	size_t i;
	uint_fast8_t keystream[16];

	while (input_size >= 16) {
		AES_encrypt(counter_block, keystream, &aes_key);
		(*counter)++;
		for (i = 0; i < 16; i++)
			output[i] = input[i] ^ keystream[i];

		input += 16;
		output += 16;
		input_size -= 16;
	}

	if (input_size > 0) {
		AES_encrypt(counter_block, keystream, &aes_key);
		(*counter)++;
		for (i = 0; i < input_size; i++)
			output[i] = input[i] ^ keystream[i];
	}
}

static inline void POLYVAL(uint_fast8_t S[16], const uint_fast8_t H[16], const uint_fast8_t *input, size_t len) {
	uint_fast8_t X[16];
	uint_fast64_t h0, h1;
	uint_fast64_t a0, a1;
	uint_fast64_t r0, r1;
	size_t i, block_len;

	memset(S, 0, 16);

	h0 = ((uint_fast64_t*)H)[0];
	h1 = ((uint_fast64_t*)H)[1];

	for (i = 0; i < len; i += 16) {
		memset(X, 0, 16);
		block_len = (len - i >= 16) ? 16 : len - i;
		memcpy(X, input + i, block_len);

		a0 = ((uint_fast64_t*)S)[0] ^ ((uint_fast64_t*)X)[0];
		a1 = ((uint_fast64_t*)S)[1] ^ ((uint_fast64_t*)X)[1];

		r0 = 0;
		r1 = 0;
		for (int b = 0; b < 64; b++) {
			if (h1 & ((uint_fast64_t)1ULL << b)) { r0 ^= a1 >> (63-b); r1 ^= a1 << b; }
			if (h0 & ((uint_fast64_t)1ULL << b)) { r0 ^= a0 >> (63-b); r1 ^= a0 << b; }
		}

		((uint_fast64_t*)S)[0] = r0 ^ 0x0101000000000000ULL;
		((uint_fast64_t*)S)[1] = r1 ^ 0xC200000000000000ULL;
	}
}

static inline int encrypt_sym(const uint_fast8_t key_generating_key[32], const uint_fast8_t nonce[12],
	const size_t nonce_size, const uint_fast8_t *input, const size_t input_size,
	const uint_fast8_t *add_data, const size_t add_data_size, uint_fast8_t *output)
{
	if (sizeof(input) > 0x1000000000 || sizeof(add_data) > 0x1000000000 || sizeof(input) <= 0 || sizeof(add_data) <= 0)
		return -1;

	AES_KEY aes_key;
	AES_set_encrypt_key(key_generating_key, 256, &aes_key);
	struct group keys;
	uint_fast8_t length_block[16] = {0}, tag[16] = {0}, i;
	uint_fast8_t *buffer = calloc(input_size + add_data_size + 16, sizeof(uint_fast8_t));
	if (!buffer) return -2;

	derive_keys(aes_key, nonce, &keys);
	*(uint_fast64_t *)length_block = (uint_fast64_t)(add_data_size * 8);
	*(uint_fast64_t *)(length_block + 8) = (uint_fast64_t)(input_size * 8);
	//Leave the padding to other functions
	memcpy(buffer, add_data, add_data_size);
	memcpy(buffer + add_data_size, input, input_size);
	memcpy(buffer + add_data_size + input_size, length_block, 16);
	POLYVAL(tag, keys.message_auth_key, buffer, add_data_size + input_size + 16);

	for (i = 0; i < 12; i++)
		tag[i] ^= nonce[i];

	tag[15] &= 0x7F;
	AES_encrypt(tag, tag, &aes_key);

	// There is ++ tag on the doc for AES-256-GCM-SIV but i think its a typo
	AES_CTR(aes_key, tag, input, input_size, output);
	free(buffer);
	return 0;
}
#endif

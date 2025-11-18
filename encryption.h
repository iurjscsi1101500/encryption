#ifndef DEFINES_H
#define DEFINES_H

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/aes.h>

struct group {
	uint_fast8_t message_auth_key[16];
	uint_fast8_t message_encryption_key[32];
};

static inline void derive_keys(const AES_KEY aes_key,
		const uint_fast8_t nonce[12],
		struct group *ptr)
{
	uint_fast8_t block[16] = {0}, out[16];
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

	uint_fast32_t *counter = (uint_fast32_t*)&counter_block[12];
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

static inline void POLYVAL(uint_fast8_t S[16], const uint_fast8_t H[16],
						   const uint_fast8_t *input, size_t len)
{
	uint_fast64_t h0, h1;
	uint_fast64_t s0, s1;
	uint_fast64_t r0, r1;
	uint_fast64_t carry;
	uint_fast64_t bit;
	uint_fast8_t block[16];
	size_t n;
	int i;

	h0 = ((uint_fast64_t*)H)[0];
	h1 = ((uint_fast64_t*)H)[1];

	s0 = 0;
	s1 = 0;

	r0 = 0;
	r1 = 0;

	while (len > 0) {

		memset(block, 0, 16);
		n = (len >= 16 ? 16 : len);
		memcpy(block, input, n);

		input += n;
		len -= n;

		s0 ^= ((uint_fast64_t*)block)[0];
		s1 ^= ((uint_fast64_t*)block)[1];

		r0 = 0;
		r1 = 0;

		for (i = 0; i < 128; i++) {

			bit = (i < 64)
				? ((s1 >> (63 - i)) & 1)
				: ((s0 >> (127 - i)) & 1);

			if (bit) {
				r0 ^= h0;
				r1 ^= h1;
			}

			carry = h1 & 1;
			h1 = (h1 >> 1) | (h0 << 63);
			h0 >>= 1;

			if (carry)
				h0 ^= 0x1c20000000000000ULL;   // POLYVAL reduction polynomial
		}

		s0 = r0;
		s1 = r1;
	}

	((uint_fast64_t*)S)[0] = s0;
	((uint_fast64_t*)S)[1] = s1;
}

static inline int encrypt_sym(const uint_fast8_t key_generating_key[32], const uint_fast8_t nonce[12],
	const uint_fast8_t *input, const size_t input_size,
	const uint_fast8_t *add_data, const size_t add_data_size,
	uint_fast8_t *output, size_t *output_size)
{
	if (input_size > 0x1000000000 || add_data_size > 0x1000000000 || input_size <= 0 || add_data_size <= 0)
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

	AES_CTR(aes_key, tag, input, input_size, output);
	memcpy(output + input_size, tag, 16);

	*output_size = input_size + 16;
	free(buffer);
	return 0;
}
static inline int decrypt_sym(const uint_fast8_t key_generating_key[32], const uint_fast8_t nonce[12],
	const uint_fast8_t *input, const size_t input_size,
	const uint_fast8_t *add_data, const size_t add_data_size,
	uint_fast8_t *output)
{
	if (input_size > 0x100000000F || add_data_size > 0x1000000000 || input_size < 16 || add_data_size <= 0)
		return -1;

	AES_KEY aes_key;
	AES_set_encrypt_key(key_generating_key, 256, &aes_key);
	struct group keys;
	uint_fast8_t tag[16] = {0}, length_block[16] = {0}, expected_tag[16] = {0}, i;

	derive_keys(aes_key, nonce, &keys);
	memcpy(tag, input + (input_size - 16), 16);

	AES_CTR(aes_key, tag, input, input_size - 16, output);

	uint_fast8_t *buffer = calloc((input_size - 16) + add_data_size + 16, sizeof(uint_fast8_t));
	if (!buffer) return -2;

	*(uint_fast64_t *)length_block = (uint_fast64_t)(add_data_size * 8);
	*(uint_fast64_t *)(length_block + 8) = (uint_fast64_t)((input_size - 16) * 8);
	//Again leave the padding to other functions

	memcpy(buffer, add_data, add_data_size);
	memcpy(buffer + add_data_size, output, input_size - 16);
	memcpy(buffer + add_data_size + (input_size - 16), length_block, 16);
	POLYVAL(expected_tag, keys.message_auth_key, buffer, add_data_size + (input_size - 16) + 16);

	for (i = 0; i < 12; i++)
		expected_tag[i] ^= nonce[i];

	expected_tag[15] &= 0x7F;
	AES_encrypt(expected_tag, expected_tag, &aes_key);

	uint_fast8_t xor_sum = 0;
	for (i = 0; i < sizeof(expected_tag); i++)
		xor_sum |= expected_tag[i] ^ tag[i];

	free(buffer);
	return xor_sum;
}
#endif

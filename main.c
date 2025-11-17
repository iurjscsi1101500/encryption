#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "encryption.h"

int main(void) {
	struct group a;
	const uint_fast8_t key_gen_key[32] = {1};
	const uint_fast8_t nonce[12] = {2};
	derive_keys(key_gen_key, nonce, &a);
	return 0;
}

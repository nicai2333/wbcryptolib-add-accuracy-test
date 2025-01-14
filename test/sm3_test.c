#include <memory.h>
#include "mbedtls/bignum.h"
#include "crypto/sm3.h"
#include "hex_utils.h"

static const uint8_t test_buf[2][64] = {
	{"abc"},
	{"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"},
};

static const int test_buflen[2] = {
	3, 64
};

static const uint8_t test_sum[2][32] = {
	/*
	 * sm3 test vectors
	 */
	{
		0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
		0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
		0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
		0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0
	},
	{
		0xDE, 0xBE, 0x9F, 0xF9, 0x22, 0x75, 0xB8, 0xA1,
		0x38, 0x60, 0x48, 0x89, 0xC1, 0x8E, 0x5A, 0x4D,
		0x6F, 0xDB, 0x70, 0xE5, 0x38, 0x7E, 0x57, 0x65,
		0x29, 0x3D, 0xCB, 0xA3, 0x9c, 0x0c, 0x57, 0x32
	}
};

int test_sm3_hash() {
	int i, ret = 0;
	unsigned char sm3sum[32];
	wbcrypto_sm3_context ctx;

	wbcrypto_sm3_init(&ctx);

	for (i = 0; i < 2; i++) {
		wbcrypto_sm3_starts(&ctx);
		wbcrypto_sm3_update(&ctx, test_buf[i], (size_t)test_buflen[i]);
		wbcrypto_sm3_finish(&ctx, sm3sum);
		if (memcmp(sm3sum, test_sum[i], 32) != 0) {
			ret = 1;
			goto cleanup;
		}
	}

cleanup:
	wbcrypto_sm3_free(&ctx);
	return (ret);
}

int main() {
	int ret = 0;
	MBEDTLS_MPI_CHK(test_sm3_hash());
cleanup:
	return ret;
}
#ifndef WBCRYPTO_TEST_HEX_UTILS_H
#define WBCRYPTO_TEST_HEX_UTILS_H

#include <stdlib.h>
#include <ctype.h>
#include "mbedtls/bignum.h"

static uint8_t hex_to_quadbit(char ch) {
	return isdigit(ch) ? ch - '0' : (ch - 'A' + 10);
}

static char quadbit_to_hex(uint8_t val) {
	val = val & 0x0F;
	return val > 9 ? val - 10 + 'A' : val + '0';
}

static void hex_to_binary(const char* hex, unsigned char* binary, size_t binary_buflen) {
	int binary_put = 0;
	int hex_used = 0;
	while (binary_put < binary_buflen && hex[hex_used] != '\0' && hex[hex_used + 1] != '\0') {
		if (isalnum(hex[hex_used])) {
			binary[binary_put] = hex_to_quadbit(hex[hex_used]) << 4 | hex_to_quadbit(hex[hex_used + 1]);
			binary_put++;
			hex_used++;//extra char consumed
		}
		hex_used++;
	}
}

static void binary_to_hex(const char* binary, char* hex, size_t hex_buflen) {
	int i = 0;
	for (; i < hex_buflen - 1; i += 2) {
		hex[i] = quadbit_to_hex(binary[i / 2] >> 4);
		hex[i + 1] = quadbit_to_hex(binary[i / 2]);
	}
	hex[hex_buflen - 1] = '\0';
}

static void print_buf_in_hex(const char* prelude, const char* buf, size_t buflen) {
	char* chars = (char*)calloc(buflen * 2 + 1, 1);
	binary_to_hex(buf, chars, buflen * 2 + 1);
	if (prelude != NULL) {
		printf("%s:", prelude);
	}
	printf("%s\n", chars);
	free(chars);
}

static void print_mpi(const char* prelude, mbedtls_mpi* mpi) {
	char buf[4096];
	size_t used;
	mbedtls_mpi_write_string(mpi, 16, buf, sizeof(buf), &used);
	if (prelude != NULL) {
		printf("%s:", prelude);
	}
	printf("%s", buf);
}

//return hex provided by ctx as random
static int mock_rand_hex(void* ctx, unsigned char* msg, size_t size) {
	mbedtls_mpi k;
	mbedtls_mpi_init(&k);
	mbedtls_mpi_read_string(&k, 16, (const char*)ctx);
	mbedtls_mpi_write_binary(&k, msg, size);
	mbedtls_mpi_free(&k);
	return 0;
}
#endif
#include <ctype.h>
#include <string.h>
#include <stdint.h>
#include "crypto/sm2.h"
#include "wbcrypto/internal/sm2/sm2_utils.h"
#include "test_data.h"
#include "../hex_utils.h"

char expected_kdf[] = "983BCF106AB2DCC92F8AEAC6C60BF298BB0117";

char kdf_bufinput[] = "0083E628CF701EE3141E8873FE55936ADF24963F5DC9C6480566C80F8A1D8CC51B01524C647F0C0412DEFD468BDA3AE0E5A80FCC8F5C990FEE11602929232DCD9F36";

int test_kdf() {
	int ret = 0;

	unsigned char buf[128] = { 0 };
	hex_to_binary(kdf_bufinput, buf, 128);

	unsigned char actual[64] = { 0 };

	unsigned char expected[64] = { 0 };
	hex_to_binary(expected_kdf, expected, 64);

	MBEDTLS_MPI_CHK(kdf(
		actual,
		buf, (sizeof(kdf_bufinput) - 1) / 2,
		152 / 8
	));

	MBEDTLS_MPI_CHK(strncmp((char*)expected, (char*)actual, 64));

cleanup:
	return ret;
}


// ENCRYPTION & DECRYPTION TESTS
char encrypt_rand_value[] = "4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F";
char plaintext[] = "encryption standard";

char expected_rawByte_ciphertext[] = "\
04245C26FB68B1DDDDB12C4B6BF9F2B6D5FE60A383B0D18D1C4144ABF17F6252\
E776CB9264C2A7E88E52B19903FDC47378F605E36811F5C07423A24B84400F01\
B8650053A89B41C418B0C3AAD00D886C002864679C3D7360C30156FAB7C80A02\
76712DA9D8094A634B766D3A285E07480653426D\
";

int test_encrypt_rawBytes_works(wbcrypto_sm2_context* ctx) {
	int ret = 0;

	unsigned char expected[1024] = { 0 };
	hex_to_binary(expected_rawByte_ciphertext, expected, sizeof(expected));

	unsigned char out_buf[1024] = { 0 };
	size_t out_size = 0;

	MBEDTLS_MPI_CHK(wbcrypto_sm2_encrypt_rawBytes(
		ctx,
		(uint8_t*)plaintext, sizeof(plaintext)-1,
		out_buf, sizeof(out_buf), &out_size,
		mock_rand_hex, encrypt_rand_value
	));

	MBEDTLS_MPI_CHK(strncmp((char*)out_buf, (char*)expected, out_size));

cleanup:
	return ret;
}

int test_decrypt_rawBytes_works(wbcrypto_sm2_context* ctx) {
	int ret = 0;

	unsigned char ciphertext[1024] = { 0 };
	size_t ciphertext_size = (sizeof(expected_rawByte_ciphertext) - 1) / 2;
	hex_to_binary(expected_rawByte_ciphertext, ciphertext, sizeof(ciphertext));

	unsigned char out_buf[1024] = { 0 };
	size_t out_size = 0;

	MBEDTLS_MPI_CHK(wbcrypto_sm2_decrypt_rawBytes(
		ctx,
		ciphertext, ciphertext_size,
		out_buf, sizeof(out_buf), &out_size
	));

	MBEDTLS_MPI_CHK(strncmp((char*)out_buf, plaintext, out_size));

cleanup:
	return ret;
}


char expected_asn1_ciphertext[] = "\
307B0220245C26FB68B1DDDDB12C4B6BF9F2B6D5FE60A383B0D18D1C4144ABF17F6252E7022076CB9264C2A7E88E52B19903FDC47378F605E36811F5C07423A24B84400F01B804209C3D7360C30156FAB7C80A0276712DA9D8094A634B766D3A285E07480653426D0413650053A89B41C418B0C3AAD00D886C00286467\
";

int test_encrypt_asn1_works(wbcrypto_sm2_context* ctx) {
	int ret = 0;

	unsigned char expected[1024] = { 0 };
	hex_to_binary(expected_asn1_ciphertext, expected, sizeof(expected));

	unsigned char out_buf[1024] = { 0 };
	size_t out_size = 0;

	MBEDTLS_MPI_CHK(wbcrypto_sm2_encrypt_asn1(
		ctx,
		(unsigned char*)plaintext, sizeof(plaintext) - 1,
		out_buf, sizeof(out_buf), &out_size,
		mock_rand_hex, encrypt_rand_value
	));

	print_buf_in_hex("Ciphertxt", (char*)out_buf, out_size);

	MBEDTLS_MPI_CHK(strncmp((char*)out_buf, (char*)expected, out_size));

cleanup:
	return ret;
}

int test_decrypt_asn1_works(wbcrypto_sm2_context* ctx) {
	int ret = 0;

	unsigned char ciphertext[1024] = { 0 };
	size_t ciphertext_size = (sizeof(expected_asn1_ciphertext) - 1) / 2;
	hex_to_binary(expected_asn1_ciphertext, ciphertext, sizeof(ciphertext));

	unsigned char out_buf[1024] = { 0 };
	size_t out_size = 0;

	MBEDTLS_MPI_CHK(wbcrypto_sm2_decrypt_asn1(
		ctx,
		ciphertext, ciphertext_size,
		out_buf, sizeof(out_buf), &out_size
	));

	MBEDTLS_MPI_CHK(strncmp((char*)out_buf, plaintext, out_size));

cleanup:
	return ret;
}


int main() {
	int ret = 0;
	wbcrypto_sm2_context ctx;
	wbcrypto_sm2_context_init(&ctx);

	//load key
	MBEDTLS_MPI_CHK(read_group_from_hex(&ctx.grp, p, a, b, xG, yG, N));
	MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&ctx.d, 16, encrypt_dB));
	MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&ctx.Pb.X, 16, encrypt_xB));
	MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&ctx.Pb.Y, 16, encrypt_yB));
	MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&ctx.Pb.Z, 1));

	MBEDTLS_MPI_CHK(test_kdf());

	MBEDTLS_MPI_CHK(test_encrypt_rawBytes_works(&ctx));
	MBEDTLS_MPI_CHK(test_decrypt_rawBytes_works(&ctx));

	MBEDTLS_MPI_CHK(test_encrypt_asn1_works(&ctx));
	MBEDTLS_MPI_CHK(test_decrypt_asn1_works(&ctx));

cleanup:
	wbcrypto_sm2_context_free(&ctx);
	return ret;
}
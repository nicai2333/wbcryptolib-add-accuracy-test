#include <ctype.h>
#include <string.h>
#include <stdint.h>
#include "crypto/sm2.h"
#include "wbcrypto/internal/sm2/sm2_utils.h"
#include "test_data.h"
#include "../hex_utils.h"


char msg[] = "message digest";
char sig_rand_value[] = "6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F";


char expected_withID_rawByte_sig[] = "\
40F1EC59F793D9F49E09DCEF49130D4194F79FB1EED2CAA55BACDB49C4E755D1\
6FC6DAC32C5D5CF10C77DFB20F7C2EB667A457872FB09EC56327A67EC7DEEBE7\
";

int test_sign_withID_rawBytes_works(wbcrypto_sm2_context* ctx) {
	int ret = 0;
	
	unsigned char expected[64] = { 0 };
	size_t expected_used = sizeof(expected_withID_rawByte_sig) - 1; (void)expected_used;
	hex_to_binary(expected_withID_rawByte_sig, expected, 64);

	unsigned char out[64] = { 0 };
	size_t out_used = 0;
	
	MBEDTLS_MPI_CHK(wbcrypto_sm2_sign_withID_rawBytes(
		ctx,
		demo_user_id, sizeof(demo_user_id),
		msg, sizeof(msg) - 1,
		out, sizeof(out), &out_used,
		mock_rand_hex, sig_rand_value
	));

	MBEDTLS_MPI_CHK(memcmp(out, expected, 64));

cleanup:
	return ret;
} 

int test_verify_withID_rawBytes_works(wbcrypto_sm2_context* ctx) {
	int ret = 0;
	
	unsigned char expected[64] = { 0 };
	hex_to_binary(expected_withID_rawByte_sig, expected, 64);

	MBEDTLS_MPI_CHK(wbcrypto_sm2_verify_withID_rawBytes(
		ctx,
		demo_user_id, sizeof(demo_user_id),
		msg, sizeof(msg) - 1,
		expected, sizeof(expected)
	));

cleanup:
	return ret;
}


char expected_rawByte_sig[] = "\
3BFC0AFCA761708339BC9793F5717515F55EDC21635D3B4291A6D0FDD43E5ACA2B27126576D6793E901AAD2DD362251B7B2A10F470E71D3AFAF3BC42541F9772\
";

int test_sign_rawBytes_works(wbcrypto_sm2_context* ctx) {
	int ret = 0;

	unsigned char expected[64] = { 0 };
	size_t expected_used = sizeof(expected_rawByte_sig) - 1; (void)expected_used;
	hex_to_binary(expected_rawByte_sig, expected, 64);

	unsigned char out[64] = { 0 };
	size_t out_used = 0;

	MBEDTLS_MPI_CHK(wbcrypto_sm2_sign_rawBytes(
		ctx,
		(uint8_t*)msg, sizeof(msg) - 1,
		out, sizeof(out), &out_used,
		mock_rand_hex, sig_rand_value
	));

	ret = memcmp(out, expected, 64);

cleanup:
	return ret;
}

int test_verify_rawBytes_works(wbcrypto_sm2_context* ctx) {
	int ret = 0;

	unsigned char expected[64] = { 0 };
	hex_to_binary(expected_rawByte_sig, expected, 64);

	MBEDTLS_MPI_CHK(wbcrypto_sm2_verify_rawBytes(
		ctx,
		(uint8_t*)msg, sizeof(msg) - 1,
		expected, sizeof(expected)
	));

cleanup:
	return ret;
}


char expected_withID_asn1_sig[] = "\
3044022040F1EC59F793D9F49E09DCEF49130D4194F79FB1EED2CAA55BACDB49C4E755D102206FC6DAC32C5D5CF10C77DFB20F7C2EB667A457872FB09EC56327A67EC7DEEBE7\
";

int test_sign_withID_asn1_works(wbcrypto_sm2_context* ctx) {
	int ret = 0;

	unsigned char expected[128] = { 0 };
	size_t expected_used = sizeof(expected_withID_asn1_sig) - 1; (void)expected_used;
	hex_to_binary(expected_withID_asn1_sig, expected, 128);

	unsigned char out[128] = { 0 };
	size_t out_used = 0;

	MBEDTLS_MPI_CHK(wbcrypto_sm2_sign_withID_asn1(
		ctx,
		demo_user_id, sizeof(demo_user_id),
		msg, sizeof(msg) - 1,
		out, sizeof(out), &out_used,
		mock_rand_hex, sig_rand_value
	));

	MBEDTLS_MPI_CHK(memcmp(out, expected, 64));

cleanup:
	return ret;
}

int test_verify_withID_asn1_works(wbcrypto_sm2_context* ctx) {
	int ret = 0;

	unsigned char expected[128] = { 0 };
	hex_to_binary(expected_withID_asn1_sig, expected, 128);

	MBEDTLS_MPI_CHK(wbcrypto_sm2_verify_withID_asn1(
		ctx,
		demo_user_id, sizeof(demo_user_id),
		msg, sizeof(msg) - 1,
		expected, sizeof(expected)
	));

cleanup:
	return ret;
}


char expected_asn1_sig[] = "\
304402203BFC0AFCA761708339BC9793F5717515F55EDC21635D3B4291A6D0FDD43E5ACA02202B27126576D6793E901AAD2DD362251B7B2A10F470E71D3AFAF3BC42541F9772\
";

int test_sign_asn1_works(wbcrypto_sm2_context* ctx) {
	int ret = 0;

	unsigned char expected[128] = { 0 };
	size_t expected_used = sizeof(expected_asn1_sig) - 1; (void)expected_used;
	hex_to_binary(expected_asn1_sig, expected, 128);

	unsigned char out[128] = { 0 };
	size_t out_used = 0;

	MBEDTLS_MPI_CHK(wbcrypto_sm2_sign_asn1(
		ctx,
		(uint8_t*)msg, sizeof(msg) - 1,
		out, sizeof(out), &out_used,
		mock_rand_hex, sig_rand_value
	));

	MBEDTLS_MPI_CHK(strncmp((char*)out, (char*)expected, 64));

cleanup:
	return ret;
}

int test_verify_asn1_works(wbcrypto_sm2_context* ctx) {
	int ret = 0;

	unsigned char expected[128] = { 0 };
	hex_to_binary(expected_asn1_sig, expected, 128);

	MBEDTLS_MPI_CHK(wbcrypto_sm2_verify_asn1(
		ctx,
		(uint8_t*)msg, sizeof(msg) - 1,
		expected, sizeof(expected)
	));

cleanup:
	return ret;
}


int main() {
	int ret = 0;
	wbcrypto_sm2_context ctx;
	wbcrypto_sm2_context_init(&ctx);

	//load key
	MBEDTLS_MPI_CHK(read_group_from_hex(&ctx.grp, p, a, b, xG, yG, N));
	MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&ctx.d, 16, sign_dA));
	MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&ctx.Pb.X, 16, sign_xA));
	MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&ctx.Pb.Y, 16, sign_yA));
	MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&ctx.Pb.Z, 1));

	MBEDTLS_MPI_CHK(test_sign_withID_rawBytes_works(&ctx));
	MBEDTLS_MPI_CHK(test_verify_withID_rawBytes_works(&ctx));
	MBEDTLS_MPI_CHK(test_sign_rawBytes_works(&ctx));
	MBEDTLS_MPI_CHK(test_verify_rawBytes_works(&ctx));

	MBEDTLS_MPI_CHK(test_sign_withID_asn1_works(&ctx));
	MBEDTLS_MPI_CHK(test_verify_withID_asn1_works(&ctx));
	MBEDTLS_MPI_CHK(test_sign_asn1_works(&ctx));
	MBEDTLS_MPI_CHK(test_verify_asn1_works(&ctx));

cleanup:
	wbcrypto_sm2_context_free(&ctx);
	return ret;
}
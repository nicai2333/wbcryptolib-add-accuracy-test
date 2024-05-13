#include "string.h"
#include "keygen.h"
#include "../hex_utils.h"

char rand_value[] = "4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F";

int test_sign_verify(wbcrypto_wbsm2_public_key* pubkey, wbcrypto_wbsm2_private_key_segment* A, wbcrypto_wbsm2_private_key_segment* B) {
	int ret = 0;
	char msg_buf[] = "signature standard";
	uint8_t sig_buf[1024] = { 0 };
	size_t sig_len = 0;

	wbcrypto_wbsm2_sign_session sign_ctx;

	wbcrypto_wbsm2_sign_session_init(&sign_ctx);
	
	MBEDTLS_MPI_CHK(
		wbcrypto_wbsm2_sign_stepA(
			pubkey,
			A,
			&sign_ctx,
			(uint8_t*)msg_buf, sizeof(msg_buf) - 1,
			mock_rand_hex, rand_value
		)
	);

	MBEDTLS_MPI_CHK(
		wbcrypto_wbsm2_sign_stepB(
			pubkey,
			B,
			&sign_ctx,
			mock_rand_hex, rand_value
		)
	);
	
	MBEDTLS_MPI_CHK(
		wbcrypto_wbsm2_sign_complete(
			pubkey,
			A,
			&sign_ctx,
			sig_buf, sizeof(sig_buf), &sig_len
	));

	MBEDTLS_MPI_CHK(wbcrypto_wbsm2_verify(
		pubkey,
		(uint8_t*)msg_buf, sizeof(msg_buf) - 1,
		sig_buf, sig_len
	));

cleanup:
	wbcrypto_wbsm2_sign_session_free(&sign_ctx);
	return ret;
}

int main() {
	int ret = 0;
	wbcrypto_wbsm2_public_key pubkey;
	wbcrypto_wbsm2_private_key_segment A, B;

	wbcrypto_wbsm2_public_key_init(&pubkey);
	wbcrypto_wbsm2_load_default_group(&pubkey.grp);
	wbcrypto_wbsm2_private_key_segment_init(&A);
	wbcrypto_wbsm2_private_key_segment_init(&B);
	
	MBEDTLS_MPI_CHK(keygen(&pubkey, &A, &B, rand_value));
	MBEDTLS_MPI_CHK(test_sign_verify(&pubkey, &A, &B));

cleanup:
	wbcrypto_wbsm2_public_key_free(&pubkey);
	wbcrypto_wbsm2_private_key_segment_free(&A);
	wbcrypto_wbsm2_private_key_segment_free(&B);
	return ret;
}
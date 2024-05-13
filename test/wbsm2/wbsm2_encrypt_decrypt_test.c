#include "string.h"
#include "keygen.h"
#include "../hex_utils.h"

char rand_value[] = "4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F";

int test_encrypt_decrypt(wbcrypto_wbsm2_public_key* pubkey, wbcrypto_wbsm2_private_key_segment* segmentA, wbcrypto_wbsm2_private_key_segment* segmentB) {
	int ret;
	char msg_buf[] = "encryption standard";
	char ciphertext_buf[1024] = { 0 };
	size_t ciphertext_len = 0;
	char recovered_buf[1024] = { 0 };
	size_t recovered_len = 0;

	wbcrypto_wbsm2_decrypt_session decrypt_ctx;

	wbcrypto_wbsm2_decrypt_session_init(&decrypt_ctx);

	MBEDTLS_MPI_CHK(
		wbcrypto_wbsm2_encrypt(
			pubkey,
			(uint8_t*)msg_buf, sizeof(msg_buf)-1,
			(uint8_t*)ciphertext_buf, sizeof(ciphertext_buf), &ciphertext_len,
			mock_rand_hex, rand_value
		)
	);
	
	MBEDTLS_MPI_CHK(
		wbcrypto_wbsm2_decrypt_stepA(
			pubkey,
			segmentA,
			&decrypt_ctx,
			(uint8_t*)ciphertext_buf, ciphertext_len
		)
	);

	MBEDTLS_MPI_CHK(
		wbcrypto_wbsm2_decrypt_stepB(
			pubkey,
			segmentB,
			&decrypt_ctx,
			mock_rand_hex, rand_value
		)
	);

	MBEDTLS_MPI_CHK(
		wbcrypto_wbsm2_decrypt_complete(
			pubkey,
			segmentA,
			&decrypt_ctx,
			(uint8_t*)ciphertext_buf, ciphertext_len,
			(uint8_t*)recovered_buf, sizeof(recovered_buf), &recovered_len
		));

	MBEDTLS_MPI_CHK(memcmp(recovered_buf, msg_buf, sizeof(msg_buf)-1));

cleanup:
	wbcrypto_wbsm2_decrypt_session_free(&decrypt_ctx);
	return ret;
}

int main() {
	int ret;
	wbcrypto_wbsm2_public_key pubkey;
	wbcrypto_wbsm2_private_key_segment A, B;

	wbcrypto_wbsm2_public_key_init(&pubkey);
	wbcrypto_wbsm2_load_default_group(&pubkey.grp);
	wbcrypto_wbsm2_private_key_segment_init(&A);
	wbcrypto_wbsm2_private_key_segment_init(&B);

	MBEDTLS_MPI_CHK(keygen(&pubkey, &A, &B, rand_value));
	MBEDTLS_MPI_CHK(test_encrypt_decrypt(&pubkey, &A, &B));

cleanup:
	wbcrypto_wbsm2_public_key_free(&pubkey);
	wbcrypto_wbsm2_private_key_segment_free(&A);
	wbcrypto_wbsm2_private_key_segment_free(&B);
	return ret;
}
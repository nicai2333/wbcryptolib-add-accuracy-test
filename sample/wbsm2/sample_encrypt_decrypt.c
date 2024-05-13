/**
 * Sample: Encrypt & Decrypt
 * this sample demonstrates the capability of encrypt & decrypt with WBSM2 algorithm
 */
#include "wbcrypto/wbsm2.h"
#include "hex_utils.h"
#include "commons/sample_common_drbg.h"
#include "commons/sample_common_keys.h"

#define ASSERT_SUCCESS(func)       \
    do                           \
    {                            \
        if( ( ret = (func) ) != 0 ) \
            goto cleanup;        \
    } while( 0 )


// instead of generating all the keys, we now load them manually to exhibit another way of doing it
//    this is done in sample_common_keys.c


//the plaintexts
char plaintext_buffer[] = "White Box SM2 Crypto Algorithm";
size_t plaintext_size = 30;

//the ciphertexts
uint8_t ciphertext_buffer[4096] = { 0 };
size_t ciphertext_size = 0;

uint8_t recovered_buffer[4096] = { 0 };
size_t recovered_size = 0;


// the encryption procedure
int sample_encryption() {
	int ret;

	//run encrypt algorithm
	ASSERT_SUCCESS(wbcrypto_wbsm2_encrypt(
		&pubkey,
		plaintext_buffer, plaintext_size,
		ciphertext_buffer, sizeof(ciphertext_buffer), &ciphertext_size,
		mbedtls_hmac_drbg_random, &hmac_drbg
	));

	//done!
	printf("encryption success!\n");
	print_buf_in_hex("ciphertext", ciphertext_buffer, ciphertext_size);
	
cleanup:
	return ret;
}

// the encryption procedure
int sample_decryption() {
	int ret;
	
	//the session for decrypt
	wbcrypto_wbsm2_decrypt_session session;
	
	//we do basic context initialization......
	wbcrypto_wbsm2_decrypt_session_init(&session);

	// decrypt process //

	ASSERT_SUCCESS(wbcrypto_wbsm2_decrypt_stepA(
		&pubkey, &segmentA,
		&session,
		ciphertext_buffer, ciphertext_size
	));

	ASSERT_SUCCESS(wbcrypto_wbsm2_decrypt_stepB(
		&pubkey, &segmentB,
		&session,
		mbedtls_hmac_drbg_random, &hmac_drbg
	));

	ASSERT_SUCCESS(wbcrypto_wbsm2_decrypt_complete(
		&pubkey, &segmentA,
		&session,
		ciphertext_buffer, ciphertext_size,
		recovered_buffer, sizeof(recovered_buffer), &recovered_size
	));

	//done!
	printf("\ndecryption success!");
	print_buf_in_hex("\nplaintext", plaintext_buffer, plaintext_size);
	print_buf_in_hex("\nrecovered", recovered_buffer, recovered_size);
	
cleanup:
	//cleanup session
	wbcrypto_wbsm2_decrypt_session_free(&session);
	return ret;
}

int main() {
	int ret;
	
	//setup
	ASSERT_SUCCESS(setup_drbg());
	ASSERT_SUCCESS(setup_wbsm2_keys());

	//run actual samples
	ASSERT_SUCCESS(sample_encryption());
	ASSERT_SUCCESS(sample_decryption());

cleanup:
	teardown_wbsm2_keys();
	teardown_drbg();
	return ret;
}

/**
 * Sample: Sign & Verify
 * this sample demonstrates the capability of sign & verify with WBSM2 algorithm
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

//the signature
uint8_t signature_buffer[4096] = { 0 };
size_t signature_size = 0;



// the signing procedure
int sample_signature() {
	int ret;

	//the session struct for signature
	wbcrypto_wbsm2_sign_session session;

	//context init
	wbcrypto_wbsm2_sign_session_init(&session);

	//run the procedure
	ASSERT_SUCCESS(wbcrypto_wbsm2_sign_stepA(
		&pubkey, &segmentA,
		&session,
		//note, since SM2 signature algorithm allows custom UserID, 
		//    there is a _withID variant that you can pass in UserID here
		//    this function use the default UserID defined by the spec
		plaintext_buffer, plaintext_size,
		mbedtls_hmac_drbg_random, &hmac_drbg
	));

	ASSERT_SUCCESS(wbcrypto_wbsm2_sign_stepB(
		&pubkey, &segmentB,
		&session,
		mbedtls_hmac_drbg_random, &hmac_drbg
	));

	ASSERT_SUCCESS(wbcrypto_wbsm2_sign_complete(
		&pubkey, &segmentA,
		&session,
		signature_buffer, sizeof(signature_buffer), &signature_size
	));


	//done!
	printf("signature success!\n");
	print_buf_in_hex("signature", signature_buffer, signature_size);
	
cleanup:
	//context cleanup
	wbcrypto_wbsm2_sign_session_free(&session);
	return ret;
}

// the encryption procedure
int sample_verify() {
	int ret = 0;
	uint8_t some_random_junk[1024];
	
	// verify process //

	//sucess on correct input
	int verify_result = wbcrypto_wbsm2_verify(
			&pubkey,
			plaintext_buffer, plaintext_size,
			signature_buffer, signature_size
	);

	if(verify_result == 0) {
		printf("\n verification of correct input success!");
	} else {
		//nope, not supposed to happen
		ret = -1;
		goto cleanup;
	}

	//fail on invalid input
	verify_result = wbcrypto_wbsm2_verify(
		&pubkey,
		some_random_junk, plaintext_size,
		signature_buffer, signature_size
	);
	
	if (verify_result == WBCRYPTO_ERR_WBSM2_VERIFY_FAILED) {
		printf("\n rejection of incorrect signature success!");
	} else {
		//nope, not supposed to happen
		ret = -1;
		goto cleanup;
	}
	
cleanup:
	return ret;
}

int main() {
	int ret;
	
	//setup
	ASSERT_SUCCESS(setup_drbg());
	ASSERT_SUCCESS(setup_wbsm2_keys());

	//run actual samples
	ASSERT_SUCCESS(sample_signature());
	ASSERT_SUCCESS(sample_verify());

cleanup:
	teardown_wbsm2_keys();
	teardown_drbg();
	return ret;
}

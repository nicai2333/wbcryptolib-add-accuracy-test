/**
 * Sample: generate WBSM2 keys
 * this sample demonstrates how to generate WBSM2 keypair
 */
#include "hex_utils.h"
#include "wbcrypto/wbsm2.h"
#include "commons/sample_common_drbg.h"

#define ASSERT_SUCCESS(func)       \
    do                           \
    {                            \
        if( ( ret = (func) ) != 0 ) \
            goto cleanup;        \
    } while( 0 )


//run the keygen algorithm
int sample_keygen() {
	int ret;
	
	//the public key part of WBSM2
	wbcrypto_wbsm2_public_key pubkey;
	//the private key is consisted of two parts: segmentA & segmentB
	wbcrypto_wbsm2_private_key_segment segmentA, segmentB;

	//do basic init 
	wbcrypto_wbsm2_public_key_init(&pubkey);
	wbcrypto_wbsm2_private_key_segment_init(&segmentA);
	wbcrypto_wbsm2_private_key_segment_init(&segmentB);

	//then we pick a group to work on (we only support default_group so far)
	ASSERT_SUCCESS(wbcrypto_wbsm2_load_default_group(&pubkey.grp));

	//then run the algorithm!
	ASSERT_SUCCESS(
		wbcrypto_wbsm2_generate_key(
			&pubkey,
			&segmentA, &segmentB,
			mbedtls_hmac_drbg_random, &hmac_drbg
		)
	);

	// done! the key is generated, you can do whatever you want with it
	printf("successfully generated key:");
	//grp is always default_group, so we don't print things about it
	print_mpi("\npubkey/P/x", &pubkey.P.X);
	print_mpi("\npubkey/P/y", &pubkey.P.Y);
	print_mpi("\npubkey/P/z", &pubkey.P.Z);

	print_mpi("\nsegmentA/hd", &segmentA.hd);
	print_mpi("\nsegmentA/W/x", &segmentA.W.X);
	print_mpi("\nsegmentA/W/y", &segmentA.W.Y);
	print_mpi("\nsegmentA/W/z", &segmentA.W.Z);

	print_mpi("\nsegmentB/hd", &segmentB.hd);
	print_mpi("\nsegmentB/W/x", &segmentB.W.X);
	print_mpi("\nsegmentB/W/y", &segmentB.W.Y);
	print_mpi("\nsegmentB/W/z", &segmentB.W.Z);
cleanup:
	//cleanup here
	wbcrypto_wbsm2_public_key_free(&pubkey);
	wbcrypto_wbsm2_private_key_segment_free(&segmentA);
	wbcrypto_wbsm2_private_key_segment_free(&segmentB);
	return ret;
}

int main() {
	int ret;
	
	//setup the RNG to use
	ASSERT_SUCCESS(setup_drbg());
	
	//run actual keygen
	ASSERT_SUCCESS(sample_keygen());
	
cleanup:
	//cleanup the RNG
	teardown_drbg();
	return ret;
}

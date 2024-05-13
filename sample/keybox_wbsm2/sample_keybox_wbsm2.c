/**
 * sample: WBSM2 KeyBox
 * This sample demonstrates the keybox storage service for WBSM2 Algorithm.
 *
 * The keybox service is designed with flexibility in mind,
 *     you can freely decide what to serialize and what part of serialized data to load
 */

#include "wbcrypto/wbsm2.h"
#include "hex_utils.h"
#include "commons/sample_common_drbg.h"
#include "commons/sample_common_keys.h"
#include <string.h>

#define ASSERT_SUCCESS(func)       \
    do                           \
    {                            \
        if( ( ret = (func) ) != 0 ) \
            goto cleanup;        \
    } while( 0 )


//utility method for copying
int ecp_point_copy(struct mbedtls_ecp_point* dst, struct  mbedtls_ecp_point* src) {
    int ret;
    ASSERT_SUCCESS(mbedtls_mpi_copy(&dst->X, &src->X));
    ASSERT_SUCCESS(mbedtls_mpi_copy(&dst->Y, &src->Y));
    ASSERT_SUCCESS(mbedtls_mpi_copy(&dst->Z, &src->Z));
cleanup:
    return ret;
}

uint8_t serialized[1024] = { 0 };
size_t serialized_size = 0;

uint8_t serialized_segmentA[1024] = { 0 };
size_t serialized_segmentA_size = 0;

uint8_t serialized_segmentB[1024] = { 0 };
size_t serialized_segmentB_size = 0;

uint8_t key[16] = "1234567890ABCDE";

/**
 * Sample: As-A-Whole storage
 *     a typical way of using it is to serialize everything in a single place, this is the most basic way of using it
 */
int sample_serialize_as_a_whole() {
    int ret;

	//the keybox
    wbcrypto_keybox_wbsm2 keybox;

	//init
    wbcrypto_keybox_wbsm2_init(&keybox);

	//// load the things you want to save ////
    ASSERT_SUCCESS(wbcrypto_wbsm2_load_default_group(&keybox.pubkey.grp));
    ASSERT_SUCCESS(ecp_point_copy(&keybox.pubkey.P, &pubkey.P));
	//you have to set a bit flag to tell us you have set it up properly
	//this is to prevent accidentally saving what you have not loaded
    keybox.loaded |= WBCRYPTO_KEYBOX_WBSM2_PUBLIC_KEY;
	
	//do the same for private segments
    ASSERT_SUCCESS(mbedtls_mpi_copy(&keybox.segmentA.hd, &segmentA.hd));
    ASSERT_SUCCESS(ecp_point_copy(&keybox.segmentA.W, &segmentA.W));
    keybox.loaded |= WBCRYPTO_KEYBOX_WBSM2_PRIVATE_SEGMENT_A;
	
    ASSERT_SUCCESS(mbedtls_mpi_copy(&keybox.segmentB.hd, &segmentB.hd));
    ASSERT_SUCCESS(ecp_point_copy(&keybox.segmentB.W, &segmentB.W));
    keybox.loaded |= WBCRYPTO_KEYBOX_WBSM2_PRIVATE_SEGMENT_B;

    //set the IV for encryption
    memcpy(keybox.iv, "1234567890ABCDE", 16);
	
    //now we save it
    ASSERT_SUCCESS(
        wbcrypto_keybox_wbsm2_save(
			&keybox,
            key, sizeof(key),
            serialized, sizeof(serialized), &serialized_size,
            //here is where you decide what to save
            //    note1: ALL is or of all components!
            //        other values can be WBCRYPTO_KEYBOX_WBSM2_PRIVATE_SEGMENT_A | WBCRYPTO_KEYBOX_WBSM2_PRIVATE_SEGMENT_B for all private parts etc.....
            //    note2: you can only save what you have 'loaded', eg. if you remove the SEGMENT_A loading above, it will fail!
            WBCRYPTO_KEYBOX_WBSM2_ALL
        )
    );


    printf("\nserialization as a whole success!");
    print_buf_in_hex("\nkeybox", serialized, serialized_size);
	
cleanup:
	//remember to clean it up
    wbcrypto_keybox_wbsm2_free(&keybox);
    return ret;
}

/**
 * Sample: separated storage
 *     use this if you want to split the segmentA & segmentB into two different places for more security
 *
 * PS: we omitted public key for brevity, you can add it if you want
 */
int sample_serialize_separated() {
    int ret;

    //the keybox
    wbcrypto_keybox_wbsm2 keybox;

    //init
    wbcrypto_keybox_wbsm2_init(&keybox);

    //// load and setup, we also load public key here for completeness, it wont be stored anyway ////
    ASSERT_SUCCESS(wbcrypto_wbsm2_load_default_group(&keybox.pubkey.grp));
    ASSERT_SUCCESS(ecp_point_copy(&keybox.pubkey.P, &pubkey.P));
    //you have to set a bit flag to tell us you have set it up properly
    //this is to prevent accidentally saving what you have not loaded
    keybox.loaded |= WBCRYPTO_KEYBOX_WBSM2_PUBLIC_KEY;

    //do the same for private segments
    ASSERT_SUCCESS(mbedtls_mpi_copy(&keybox.segmentA.hd, &segmentA.hd));
    ASSERT_SUCCESS(ecp_point_copy(&keybox.segmentA.W, &segmentA.W));
    keybox.loaded |= WBCRYPTO_KEYBOX_WBSM2_PRIVATE_SEGMENT_A;

    ASSERT_SUCCESS(mbedtls_mpi_copy(&keybox.segmentB.hd, &segmentB.hd));
    ASSERT_SUCCESS(ecp_point_copy(&keybox.segmentB.W, &segmentB.W));
    keybox.loaded |= WBCRYPTO_KEYBOX_WBSM2_PRIVATE_SEGMENT_B;

    //set the IV for encryption
    memcpy(keybox.iv, "1234567890ABCDE", 16);

    //now we save segmentA in one buffer
    ASSERT_SUCCESS(
        wbcrypto_keybox_wbsm2_save(
            &keybox,
            key, sizeof(key),
            serialized_segmentA, sizeof(serialized_segmentA), &serialized_segmentA_size,
            //although we loaded everything, but we only save segmentA due to this flag
            WBCRYPTO_KEYBOX_WBSM2_PRIVATE_SEGMENT_A
        )
    );

    //B in another
	//note: change the IV if you want, then this keybox will use that IV
    ASSERT_SUCCESS(
        wbcrypto_keybox_wbsm2_save(
            &keybox,
            key, sizeof(key),
            serialized_segmentB, sizeof(serialized_segmentB), &serialized_segmentB_size,
            WBCRYPTO_KEYBOX_WBSM2_PRIVATE_SEGMENT_B
        )
    );

    printf("\nserialization separately success!");
    print_buf_in_hex("\nkeybox-segmentA", serialized_segmentA, serialized_segmentA_size);
    print_buf_in_hex("\nkeybox-segmentB", serialized_segmentB, serialized_segmentB_size);

cleanup:
    //remember to clean it up
    wbcrypto_keybox_wbsm2_free(&keybox);
    return ret;
}


/**
 * Sample: As-A-Whole storage
 *     a typical way of using it is to load everything from a single place, this is the most basic way of using it
 */
int sample_deserialize_as_a_whole() {
    int ret;

    //the keybox
    wbcrypto_keybox_wbsm2 keybox;

    //init
    wbcrypto_keybox_wbsm2_init(&keybox);

    //now we load everything
    ASSERT_SUCCESS(
        wbcrypto_keybox_wbsm2_load(
            &keybox,
            key, sizeof(key),
            serialized, serialized_size,
            //btw, it will still success if the serialized form does not contain ALL 
            WBCRYPTO_KEYBOX_WBSM2_ALL
        )
    );

    //so we must check it manually to ensure success!
    if (keybox.loaded != WBCRYPTO_KEYBOX_WBSM2_ALL) {
        ret = -1;
        goto cleanup;
    }

    printf("\ndeserialization as a whole success!");

cleanup:
    //remember to clean it up
    wbcrypto_keybox_wbsm2_free(&keybox);
    return ret;
}

/**
 * Sample: separated storage
 *     use this if you want to split the segmentA & segmentB into two different places for more security
 *
 * PS: we omitted public key for brevity, you can add it if you want
 * PS: the loading procedures below can also work with serialize_as_a_whole(), but that would not separate two private keys's storage
 *     but make them only decrypt and show up in memory on needed
 */
int sample_deserialize_separated() {
    int ret;

    //the keybox
    wbcrypto_keybox_wbsm2 keybox;

    //init
    wbcrypto_keybox_wbsm2_init(&keybox);

    //now we load segmentA here
    ASSERT_SUCCESS(
        wbcrypto_keybox_wbsm2_load(
            &keybox,
            key, sizeof(key),
            serialized_segmentA, serialized_segmentA_size,
            //we now limit this to PRIVATE_SEGMENT_A
            WBCRYPTO_KEYBOX_WBSM2_PRIVATE_SEGMENT_A
        )
    );

	//only PRIVATE_SEGMENT_A got loaded
    if(keybox.loaded != WBCRYPTO_KEYBOX_WBSM2_PRIVATE_SEGMENT_A) {
        ret = -1;
        goto cleanup;
    }

	// do something with segmentA ......

	//wipe segmentA for security
    wbcrypto_wbsm2_private_key_segment_free(&keybox.segmentA);
    wbcrypto_wbsm2_private_key_segment_init(&keybox.segmentA);
    keybox.loaded &= ~WBCRYPTO_KEYBOX_WBSM2_PRIVATE_SEGMENT_A;


    //now we load segmentB here
    ASSERT_SUCCESS(
        wbcrypto_keybox_wbsm2_load(
            &keybox,
            key, sizeof(key),
            serialized_segmentB, serialized_segmentB_size,
            //now we only load PRIVATE_SEGMENT_B
            WBCRYPTO_KEYBOX_WBSM2_PRIVATE_SEGMENT_B
        )
    );

    //only PRIVATE_SEGMENT_B got loaded
    if (keybox.loaded != WBCRYPTO_KEYBOX_WBSM2_PRIVATE_SEGMENT_B) {
        ret = -1;
        goto cleanup;
    }

    //do something with segmentB......

    //wipe segmentB for security
    wbcrypto_wbsm2_private_key_segment_free(&keybox.segmentB);
    wbcrypto_wbsm2_private_key_segment_init(&keybox.segmentB);
    keybox.loaded &= ~WBCRYPTO_KEYBOX_WBSM2_PRIVATE_SEGMENT_B;

	
    printf("\ndeserialization separately success!");

cleanup:
    //remember to clean it up
    wbcrypto_keybox_wbsm2_free(&keybox);
    return ret;
}

int main() {
	int ret;

	//setup
	ASSERT_SUCCESS(setup_drbg());
	ASSERT_SUCCESS(setup_wbsm2_keys());

	//run actual samples
	ASSERT_SUCCESS(sample_serialize_as_a_whole());
	ASSERT_SUCCESS(sample_deserialize_as_a_whole());

    ASSERT_SUCCESS(sample_serialize_separated());
    ASSERT_SUCCESS(sample_deserialize_separated());

cleanup:
	teardown_wbsm2_keys();
	teardown_drbg();
	return ret;
}

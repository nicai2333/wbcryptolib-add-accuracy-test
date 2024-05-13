/*
 * The support for samples that needs keys to work
 */
#ifndef WBCRYPTO_SAMPLE_COMMON_KEYS_H_
#define WBCRYPTO_SAMPLE_COMMON_KEYS_H_
#include "wbcrypto/keybox_wbsm2.h"

// the keys available to use

//the public key part of WBSM2
extern wbcrypto_wbsm2_public_key pubkey;
//the private keys
extern wbcrypto_wbsm2_private_key_segment segmentA, segmentB;


//setup the keys, return non-zero value on failure
int setup_wbsm2_keys();

void teardown_wbsm2_keys();

#endif // !WBCRYPTO_SAMPLE_COMMON_DRBG_H_

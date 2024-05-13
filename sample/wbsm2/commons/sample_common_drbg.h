/*
 * The support for samples that needs DRBG to work
 */
#ifndef WBCRYPTO_SAMPLE_COMMON_DRBG_H_
#define WBCRYPTO_SAMPLE_COMMON_DRBG_H_
#include "mbedtls/hmac_drbg.h"
#include "mbedtls/entropy.h"

//the RNG & entropy source available to use, setup & teardown by calling functions below
extern mbedtls_entropy_context entropy;
extern mbedtls_hmac_drbg_context hmac_drbg;

//setup the drbg, return non-zero value on failure
int setup_drbg();

void teardown_drbg();

#endif // !WBCRYPTO_SAMPLE_COMMON_DRBG_H_

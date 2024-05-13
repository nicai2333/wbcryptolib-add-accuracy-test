#include "sample_common_drbg.h"
#include "mbedtls/entropy_poll.h"

#define ASSERT_SUCCESS(func)       \
    do                           \
    {                            \
        if( ( ret = (func) ) != 0 ) \
            goto cleanup;        \
    } while( 0 )

//the RNG & entropy source to use
mbedtls_entropy_context entropy;
mbedtls_hmac_drbg_context hmac_drbg;

int setup_drbg() {
	int ret;
	//we do basic context initialization......
	mbedtls_entropy_init(&entropy);
	mbedtls_hmac_drbg_init(&hmac_drbg);

	//setup the RNG & entropy
	ASSERT_SUCCESS(mbedtls_entropy_add_source(
		&entropy,
		mbedtls_platform_entropy_poll, NULL,
		MBEDTLS_ENTROPY_MIN_PLATFORM,
		MBEDTLS_ENTROPY_SOURCE_STRONG
	));

	ASSERT_SUCCESS(mbedtls_hmac_drbg_seed(
		&hmac_drbg,
		mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
		mbedtls_entropy_func, &entropy,
		"YET_ANOTHER_RANDOM_STRING", sizeof("YET_ANOTHER_RANDOM_STRING")
	));
cleanup:
	return ret;
}

void teardown_drbg() {
	mbedtls_hmac_drbg_free(&hmac_drbg);
	mbedtls_entropy_free(&entropy);
}
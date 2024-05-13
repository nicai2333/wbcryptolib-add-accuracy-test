/**
 *
 * \file md.h
 *
 * \brief This file contains the MD HMAC extension for SM3 algorithm on top of mbedtls
 *
 */
#ifndef WBCRYPTO_MD_H_
#define WBCRYPTI_MD_H_

#include "mbedtls/md.h"

#define WBCRYPTO_MD_SM3 10

#ifdef __cplusplus
extern "C" {
#endif

	int wbcrypto_md_hmac(
		const mbedtls_md_info_t* md_info,
		const unsigned char* key, size_t keylen,
		const unsigned char* input, size_t ilen,
		unsigned char* output
	);

	extern const mbedtls_md_info_t wbcrypto_sm3_md_info;

#ifdef __cplusplus
}
#endif

#endif // !WBCRYPTO_MD_H_

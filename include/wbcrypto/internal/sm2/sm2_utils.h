/**
 * \file sm2.h
 *
 * \brief This file contains the non-public utilities API of SM2 Algorithm,for testing only
 *
 */
#ifndef WBCRYPTO_INTERNAL_SM2_H
#define WBCRYPTO_INTERNAL_SM2_H

#include "mbedtls/ecp.h"

#ifdef __cplusplus
extern "C" {
#endif

	static const char sm2_default_id[] = { 0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38 };
	static const int sm2_default_id_length = 16;

	//run SM2 KDF on input
	int kdf(
		unsigned char* out,
		const unsigned char* buf, size_t buf_len, size_t klen
	);

	/*given point(x,y), write x || y*/
	int write_point_x_y(
		mbedtls_ecp_group* group, mbedtls_ecp_point* point,
		unsigned char* byte, size_t* blen
	);

	/*given x,y, write x || y, with int_length each*/
	int write_x_y(
		size_t int_length,
		mbedtls_mpi* X, mbedtls_mpi* Y,
		unsigned char* byte, size_t* blen
	);

	//given point(x2,y2) and m, write x2 || m || y2
	int write_x2_m_y2(
		mbedtls_ecp_group* group, mbedtls_ecp_point* point,
		const unsigned char* m, size_t mlen,
		unsigned char* out, size_t* olen
	);

#ifdef __cplusplus
}
#endif

#endif /* sm2_utils.h */
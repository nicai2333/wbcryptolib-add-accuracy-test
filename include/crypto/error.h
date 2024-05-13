/**
 * \file error.h
 *
 * \brief Error to string translation
 */
#ifndef WBCRYPTO_ERROR_H
#define WBCRYPTO_ERROR_H

#if !defined(WBCRYPTO_CONFIG_FILE)
#include "wbcrypto/config.h"
#else
#include WBCRYPTO_CONFIG_FILE
#endif

#include <stdint.h>
#include <stddef.h>

  /**
   * Error code layout.
   *
   * We carry the error code of MBEDTLS,but uses the 32bit error code length instead of 16bit.
   * We still keep them in negative space, and only uses the 16th bit to indicate
   * this is an error from wbcrypto instead of mbedtls,
   * so at worst case we occupy the positive space for error on 16bit machine
   *
   * the error codes are segmented in the following manner:
   *
   * <ALL BITS IN UPPER 16 bits>: all 0xFF for in negative space
   * 1 bit  - 1 for MBEDTLS 0 for WBCRYPTO  
   * 7 bits - High level module ID
   * 8 bits - Module-dependent error code
   *
   * High-level module nr (7 bits - 0x00...-0x7F...)
   * Name      ID
   * SM2       0x00
   * SM2COOP   0x01
   * RSACOOP   0x02
   * WBSM2     0x05
   * Keybox    0x0A
   * 
   */

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * \brief Translate a error code into a string representation,
	 *        Result is truncated if necessary and always includes a terminating
	 *        null byte.
	 *
	 * \param errnum    error code
	 * \param buffer    buffer to place representation in
	 * \param buflen    length of the buffer
	 */
	void wbcrypto_strerror(int32_t errnum, char* buffer, size_t buflen);

#ifdef __cplusplus
}
#endif

#endif /* error.h */

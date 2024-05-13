/**
 * \file sm3.h
 *
 * \brief This file contains the SM3 Hashing Algorithm
 */
#ifndef WBCRYPTO_SM3_H
#define WBCRYPTO_SM3_H

#include <stddef.h>
#include <stdint.h>

#define SM3_DIGEST_LENGTH    32
#define SM3_BLOCK_SIZE       64

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * \brief          SM3 context structure
	 */
	typedef struct {
		uint32_t total[2];          /*!< number of bytes processed  */
		uint32_t state[8];          /*!< intermediate digest state  */
		unsigned char buffer[64];   /*!< data block being processed */
	} wbcrypto_sm3_context;


	/**
	 * \brief          This function initializes a SM3 context.
	 *
	 * \param ctx      The SM3 context to initialize. This must not be \c NULL.
	 */
	void wbcrypto_sm3_init(wbcrypto_sm3_context* ctx);

	/**
	 * \brief          This function clears a SM3 context.
	 *
	 * \param ctx      The SM3 context to clear. This may be \c NULL, in which
	 *                 case this function returns immediately. If it is not \c NULL,
	 *                 it must point to an initialized SM3 context.
	 */
	void wbcrypto_sm3_free(wbcrypto_sm3_context* ctx);

	/**
	 * \brief          This function clones the state of a SM3 context.
	 *
	 * \param dst      The destination context. This must be initialized.
	 * \param src      The context to clone. This must be initialized.
	 */
	void wbcrypto_sm3_clone(wbcrypto_sm3_context* dst, const wbcrypto_sm3_context* src);


	/**
	 * \brief          This function starts a SM3 checksum calculation.
	 *
	 * \param ctx      The context to use. This must be initialized.
	 *
	 * \return         \c 0 on success.
	 * \return         A negative error code on failure.
	 */
	int wbcrypto_sm3_starts(wbcrypto_sm3_context* ctx);

	/**
	 * \brief          This function feeds an input buffer into an ongoing
	 *                 SM3 checksum calculation.
	 *
	 * \param ctx      The SM3 context. This must be initialized
	 *                 and have a hash operation started.
	 * \param input    The buffer holding the data. This must be a readable
	 *                 buffer of length \p ilen Bytes.
	 * \param ilen     The length of the input data in Bytes.
	 *
	 * \return         \c 0 on success.
	 * \return         A negative error code on failure.
	 */
	int wbcrypto_sm3_update(
		wbcrypto_sm3_context* ctx, 
		const unsigned char* input, size_t ilen
	);

	 /**
	  * \brief          This function finishes the SM3 peration, and writes
	  *                 the result to the output buffer.
	  *
	  * \param ctx      The SM3 context. This must be initialized
	  *                 and have a hash operation started.
	  * \param output   The SM3 checksum result.
	  *                 This must be a writable buffer of length \c 32 Bytes.
	  *
	  * \return         \c 0 on success.
	  * \return         A negative error code on failure.
	  */
	int wbcrypto_sm3_finish(wbcrypto_sm3_context* ctx, unsigned char output[32]);

	/**
	 * \brief          Output = SM3( input buffer ), compute all in one go
	 *
	 * \param input    buffer holding the input data
	 * \param ilen     length of the input data
	 * \param output   SM3 result
	 *
	 * \return         \c 0 on success.
	 * \return         A negative error code on failure.
	 */
	int wbcrypto_sm3(
		const unsigned char* input, size_t ilen,
		unsigned char output[32]
	);

	/* Internal use */
	void wbcrypto_sm3_process(wbcrypto_sm3_context* ctx, const unsigned char block[64]);

#if defined(WBCRYPTO_SELF_TEST)
	/**
	 * \brief          Checkup routine
	 *
	 * \return         0 if successful, or 1 if the test failed
	 */
	int wbcrypto_sm3_self_test(int verbose);
#endif

#ifdef __cplusplus
}
#endif

#endif /* sm3.h */
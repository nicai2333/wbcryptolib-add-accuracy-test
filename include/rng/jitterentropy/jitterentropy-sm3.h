#ifndef JITTERENTROPY_SM3_H
#define JITTERENTROPY_SM3_H

#include <stddef.h>
#include <stdint.h>
#include "rng/jitterentropy/jitterentropy.h"

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
	} sm3_context;


	/**
	 * \brief          This function initializes a SM3 context.
	 *
	 * \param ctx      The SM3 context to initialize. This must not be \c NULL.
	 */
	void sm3_init(sm3_context* ctx);

	int sm3_alloc(void **hash_state);

	void sm3_dealloc(void *hash_state);

	/**
	 * \brief          This function clears a SM3 context.
	 *
	 * \param ctx      The SM3 context to clear. This may be \c NULL, in which
	 *                 case this function returns immediately. If it is not \c NULL,
	 *                 it must point to an initialized SM3 context.
	 */
	void sm3_free(sm3_context* ctx);

	/**
	 * \brief          This function clones the state of a SM3 context.
	 *
	 * \param dst      The destination context. This must be initialized.
	 * \param src      The context to clone. This must be initialized.
	 */
	void sm3_clone(sm3_context* dst, const sm3_context* src);


	/**
	 * \brief          This function starts a SM3 checksum calculation.
	 *
	 * \param ctx      The context to use. This must be initialized.
	 *
	 * \return         \c 0 on success.
	 * \return         A negative error code on failure.
	 */
	int sm3_starts(sm3_context* ctx);

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
	int sm3_update(sm3_context* ctx, const unsigned char* input, size_t ilen);

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
	int sm3_final(sm3_context* ctx, unsigned char output[32]);

	/* Internal use */
	void sm3_process(sm3_context* ctx, const unsigned char block[64]);

	int sm3_self_test(int verbose);


#ifdef __cplusplus
}
#endif

#endif /* sm3.h */
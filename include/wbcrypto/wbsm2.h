/**
 *
 * \file wbsm2.h
 *
 * \brief This file contains the White Box SM2 algorithm definitions and functions.
 *
 */
#ifndef WBCRYPTO_WBSM2_H
#define WBCRYPTO_WBSM2_H

#if !defined(WBCRYPTO_CONFIG_FILE)
#include "crypto/config.h"
#else
#include WBCRYPTO_CONFIG_FILE
#endif

#include  "crypto/adaptive_error.h"
#include "stdint.h"
#include "mbedtls/ecp.h"
#include "mbedtls/md.h"

#define WBCRYPTO_ERR_WBSM2_GENERIC_FAILURE                   WBCRYPTO_ADAPT_ERROR(-0x0300)  /**< Unknown failure in this function. **/
#define WBCRYPTO_ERR_WBSM2_ALLOC_FAILED                      WBCRYPTO_ADAPT_ERROR(-0x0301)  /**< Failed to allocate memory. */
#define WBCRYPTO_ERR_WBSM2_SETUP_FAILED                      WBCRYPTO_ADAPT_ERROR(-0x0302)  /**< Failed to run setup function to a data struct */
#define WBCRYPTO_ERR_WBSM2_BAD_INPUT_DATA                    WBCRYPTO_ADAPT_ERROR(-0x0303)  /**< Bad input parameters to function, usually programming error */
#define WBCRYPTO_ERR_WBSM2_MALFORMED_DATA                    WBCRYPTO_ADAPT_ERROR(-0x0304)  /**< The input data is ill-formated, cannot understand it */
#define WBCRYPTO_ERR_WBSM2_OUTPUT_TOO_LARGE                  WBCRYPTO_ADAPT_ERROR(-0x0305)  /**< The output buffer for decryption is not large enough. */
#define WBCRYPTO_ERR_WBSM2_RNG_FAILED                        WBCRYPTO_ADAPT_ERROR(-0x0306)  /**< The random generator failed to generate non-zeros. */
#define WBCRYPTO_ERR_WBSM2_VERIFY_FAILED                     WBCRYPTO_ADAPT_ERROR(-0x0307)  /**< The signature does not corresponds to the message. */

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * \brief           The White Box SM2 public key structure, holds the public key to operate on
	 *
	 * \note            Please turn to ecp.h and mpi.h for value I/O
	 */
	typedef struct {
		mbedtls_ecp_group grp; /**< SHARED: Elliptic curve and base point             */
		mbedtls_ecp_point P;   /**< PUBLIC: The public key for signature verification */
	} wbcrypto_wbsm2_public_key;

	/**
	 * \brief           The White Box SM2 private key segment, holds the private key segment (has two segments) to use
	 * 
	 * \note            Please turn to ecp.h and mpi.h for value I/O
	 */
	typedef struct {
		mbedtls_ecp_point W; /**< PRIVATE: The key for signature generation */
		mbedtls_mpi hd;      /**< PRIVATE: The private key */
	} wbcrypto_wbsm2_private_key_segment;

	/**
	 * \brief           This function will load the curve specified by SM2 Standard
	 *
	 * \param grp       the group to load parameter into, must be initialized with mbedtls_ecp_group_init()!
	 *
	 * \return          0 if successful, otherwise error
	 *
	 * \note            This function will set the curve ID to MBEDTLS_ECP_DP_NONE
	 *
	 */
	int wbcrypto_wbsm2_load_default_group(mbedtls_ecp_group* grp);

	/**
	 * \brief           This function initializes the white box SM2 public key
	 *
	 * \param ctx       Context to initialize, MUST NOT be NULL
	 *
     * \note            This function will NOT initialize the public key with default SM2 curve, consider calling load_default_group(&ctx.grp)!
	 */
	void wbcrypto_wbsm2_public_key_init(wbcrypto_wbsm2_public_key* ctx);

	/**
	 * \brief          This function copies the components of an white box SM2 public key.
	 *
	 * \param dst      The destination context. This must be initialized.
	 *
	 * \param src      The source context. This must be initialized.
	 *
	 * \note           we will NOT COPY THE GROUP since this requires adding new curves to mbedtls, plz do it yourself
	 *
	 * \return         \c 0 on success, otherwise error
	 *
	 */
	int wbcrypto_wbsm2_public_key_copy(wbcrypto_wbsm2_public_key* dst, const wbcrypto_wbsm2_public_key* src);

	/**
	 * \brief          This function frees the white box sm2 public key.
	 *
	 * \param ctx      The context to free. May be \c NULL, in which case
	 *                 this function is a no-op. If it is not \c NULL, it must
	 *                 point to an initialized context.
	 */
	void wbcrypto_wbsm2_public_key_free(wbcrypto_wbsm2_public_key* ctx);


	/**
	 * \brief           This function initializes the white box SM2 private key segment
	 *
	 * \param ctx       Context to initialize, MUST NOT be NULL
	 *
	 */
	void wbcrypto_wbsm2_private_key_segment_init(wbcrypto_wbsm2_private_key_segment* ctx);

	/**
	 * \brief          This function copies the components of an white box SM2 private key segment
	 *
	 * \param dst      The destination context. This must be initialized.
	 *
	 * \param src      The source context. This must be initialized.
	 *
	 * \return         \c 0 on success, otherwise error
	 *
	 */
	int wbcrypto_wbsm2_private_key_segment_copy(wbcrypto_wbsm2_private_key_segment* dst, const wbcrypto_wbsm2_private_key_segment* src);

	/**
	 * \brief          This function frees the white box SM2 private key segment
	 *
	 * \param ctx      The context to free. May be \c NULL, in which case
	 *                 this function is a no-op. If it is not \c NULL, it must
	 *                 point to an initialized context.
	 */
	void wbcrypto_wbsm2_private_key_segment_free(wbcrypto_wbsm2_private_key_segment* ctx);

	
	/**
	 * \brief             generate a new wbsm2 public-private key pair, have 1 public key and 2 private key segment
	 *
	 * \param pubkey      the struct to hold pubkey, MUST BE INITIALIZED AND have its GRP loaded with a curve(this will be the curve of the key)
	 *
	 * \param segmentA    the struct to hold private key segment A, MUST BE INITIALIZED
	 *
	 * \param segmentB    the struct to hold private key segment B, MUST BE INITIALIZED
	 *
	 * \param f_rng       RNG function, MUST NOT BE NULL
	 *
	 * \param p_rng       RNG parameter
	 *
	 * \return            0 if success, otherwise fail
	 *
	 */
	int wbcrypto_wbsm2_generate_key(
		wbcrypto_wbsm2_public_key* pubkey,
		wbcrypto_wbsm2_private_key_segment* segmentA,
		wbcrypto_wbsm2_private_key_segment* segmentB,
		int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
	);


	/**
	 * \brief           run sm2 encryption algorithm, result is ASN.1 DER encoded
	 *
	 * \param ctx       the sm2 context, must have at least P and grp loaded
	 *
	 * \param buffer    data to encrypt, MUST NOT BE NULL
	 *
	 * \param plen      data length
	 *
	 * \param out       buffer for ciphertext, MUST NOT BE NULL
	 *
	 * \param max_olen  buffer length limit for ciphertext
	 *
	 * \param olen      pointer to return the ciphertext length, MUST NOT BE NULL
	 *
	 * \param f_rng     RNG function, MUST NOT BE NULL
	 *
	 * \param p_rng     RNG parameter
	 *
	 * \return          0 if successful, otherwise error
	 *
	 * \note            this is essentially a SM2 encrypt function
	 *
	 */
	int wbcrypto_wbsm2_encrypt(
		wbcrypto_wbsm2_public_key* ctx,
		const unsigned char* buffer, size_t	blen,
		unsigned char* out, size_t max_olen, size_t* olen,
		int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
	);


	/**
	 * \brief           The White Box SM2 Decrypt session state
	 */
	typedef struct {
		size_t total_size;
		mbedtls_ecp_point c1point;
		uint8_t* req_buf;
		size_t req_size;
		uint8_t* resp_buf;
		size_t resp_size;
		uint64_t c2_offset;
		uint64_t c2_len;
		uint64_t c3_offset;
		uint64_t c3_len;
	} wbcrypto_wbsm2_decrypt_session;

	/**
	 * \brief           This function initializes the decrypt session
	 *
	 * \param ctx       Context to initialize, MUST NOT be NULL
	 *
	 */
	void wbcrypto_wbsm2_decrypt_session_init(wbcrypto_wbsm2_decrypt_session* ctx);

	/**
	 * \brief          This function copies the components of the decrypt session.
	 *
	 * \param dst      The destination session. This must be initialized.
	 * \param src      The source session. This must be initialized.
	 *
	 * \return          0 if successful, otherwise failure
	 */
	int wbcrypto_wbsm2_decrypt_session_copy(
		wbcrypto_wbsm2_decrypt_session* dst,
		const wbcrypto_wbsm2_decrypt_session* src
	);

	/**
	 * \brief          This function frees the the decrypt session.
	 *
	 * \param ctx      The session to free. May be \c NULL, in which case
	 *                 this function is a no-op. If it is not \c NULL, it must
	 *                 point to an initialized context.
	 */
	void wbcrypto_wbsm2_decrypt_session_free(wbcrypto_wbsm2_decrypt_session* ctx);

	/**
	 * \brief           starts the sm2 decrypt protocol, use the segmentA private key
	 *						the ciphertext is assumed to be ASN.1 DER encoded, see the corresponding encrypt function for encoding details
	 *
	 * \param public_key the public key
	 * 
	 * \param segmentA the segmentA private key
	 *
	 * \param decrypt_ctx the extra session for decryption
	 *
	 * \param ciphertext    the ciphertext
	 *
	 * \param clen      the cipher byte length
	 *
	 * \return          0 if successful, otherwise failure
	 * 
	 * \note            the decrypt session should be considered invalid after failure, and should be freed immediately
	 * 
	 */
	int wbcrypto_wbsm2_decrypt_stepA(
		wbcrypto_wbsm2_public_key* public_key,
		wbcrypto_wbsm2_private_key_segment* segmentA,
		wbcrypto_wbsm2_decrypt_session* decrypt_ctx,
		const unsigned char* ciphertext, size_t clen
	);

	/**
	 * \brief           continue the decrypt protocol, use the segmentB private key
	 *
	 * \param public_key the public key
	 *
	 * \param segmentB the segmentB private key
	 *
	 * \param decrypt_ctx the extra session for decryption
	 *
	 * \param f_rng     the RNG function, MUST NOT BE NULL
	 *
	 * \param p_rng     the RNG context(1st arg of the function)
	 *
	 * \return          0 if successful, otherwise failure
	 *
	 * \note            the decrypt session should be considered invalid after failure, and should be freed immediately
	 * 
	 */
	int wbcrypto_wbsm2_decrypt_stepB(
		wbcrypto_wbsm2_public_key* public_key,
		wbcrypto_wbsm2_private_key_segment* segmentB,
		wbcrypto_wbsm2_decrypt_session* decrypt_ctx,
		int(*f_rng)(void*, unsigned char*, size_t), void* p_rng
	);


	/**
	 * \brief           completes the sm2 decrypt protocol,
	 *						the ciphertext is assumed to be ASN.1 DER encoded
	 *						see the corresponding encrypt function for encoding details
	 *
	 * \param public_key  the public key
	 *
	 * \param segmentA    the segmentA private key
	 *
	 * \param decrypt_ctx the extra session for decryption
	 *
	 * \param ciphertext  the ciphertext, MUST NOT BE NULL
	 *
	 * \param clen        the ciphertext byte length
	 *
	 * \param out         the plaintext buffer, MUST NOT BE NULL
	 *
	 * \param max_olen    max capacity of the plaintext buffer
	 *
	 * \param olen        pointer for returning plaintext length, MUST NOT BE NULL
	 *
	 * \return            0 if successful, otherwise failure
	 *
	 * \note            the decrypt session should be considered invalid after failure, and should be freed immediately
	 * 
	 */
	int wbcrypto_wbsm2_decrypt_complete(
		wbcrypto_wbsm2_public_key* public_key,
		wbcrypto_wbsm2_private_key_segment* segmentA,
		wbcrypto_wbsm2_decrypt_session* decrypt_ctx,
		const unsigned char* ciphertext, size_t clen,
		unsigned char* out, size_t max_olen, size_t* olen
	);


	/**
	 * \brief           The White Box SM2 Decrypt signature state
	 */
	typedef struct {
		mbedtls_mpi k;
		uint8_t* req_buf;
		size_t req_size;
		uint8_t* dgst_buf;
		size_t dgst_size;
		uint8_t* resp_buf;
		size_t resp_size;
	} wbcrypto_wbsm2_sign_session;

	/**
	 * \brief           This function initializes the sign session
	 *
	 * \param ctx       Session to initialize, MUST NOT be NULL
	 *
	 */
	void wbcrypto_wbsm2_sign_session_init(wbcrypto_wbsm2_sign_session* ctx);

	/**
	 * \brief          This function copies the components of the sign session.
	 *
	 * \param dst      The destination session. This must be initialized.
	 * \param src      The source session. This must be initialized.
	 *
	 * \return         0 if successful, otherwise failure
	 */
	int wbcrypto_wbsm2_sign_session_copy(
		wbcrypto_wbsm2_sign_session* dst,
		const wbcrypto_wbsm2_sign_session* src
	);

	/**
	 * \brief          This function frees the the sign session.
	 *
	 * \param ctx      The session to free. May be \c NULL, in which case
	 *                 this function is a no-op. If it is not \c NULL, it must
	 *                 point to an initialized session.
	 */
	void wbcrypto_wbsm2_sign_session_free(wbcrypto_wbsm2_sign_session* ctx);

	/**
	 * \brief           run the white box sm2 signature algorithm stepA, the result is encoded in ASN.1 DER
	 *
	 * \param pubkey    the public key
	 *
	 * \param segmentA  the segmentA private key
	 *
	 * \param sign_ctx  the signature session
	 *
	 * \param msg       the message to sign
	 *
	 * \param msglen    the length of message
	 *
	 * \param f_rng     RNG function
	 * 
	 * \param p_rng     RNG parameter
	 *
	 * \return          0 if successful, otherwise failure
	 *
	 * \note            the encoding of signature in ASN.1 is:
	 *                  SM2 Signature::= (
	 *						R INTEGER,
	 *						S INTEGER
	 *					)
	 *					The length of R and S are 32Bytes, respectively
	 *
	 * \note           Such encoding is only guranteed when using the standard curve parameter
	 *                     the length might be not 32Bytes if using other curve
	 *
	 * \note           the signature session should be considered invalid after failure, and should be freed immediately
	 * 
	 */
	int wbcrypto_wbsm2_sign_stepA(
		wbcrypto_wbsm2_public_key* pubkey,
		wbcrypto_wbsm2_private_key_segment* segmentA,
		wbcrypto_wbsm2_sign_session* sign_ctx,
		const unsigned char* msg, size_t msglen,
		int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
	);

	/**
	 * \brief           run the white box sm2 signature algorithm stepA with custom userID,
	 *                      the result is encoded as ASN.1 DER
	 *                      
	 * \param pubkey    the public key
	 *
	 * \param segmentA  the segmentA private key
	 *
	 * \param sign_ctx  the signature context
	 * 
	 * \param id        user ID, just a byte string
	 *
	 * \param idlen     id string length
	 *
	 * \param msg       the message to sign
	 *
	 * \param msglen    the length of message
	 *
	 * \param f_rng     RNG function
	 *
	 * \param p_rng     RNG parameter
	 *
	 * \return          0 if successful, otherwise failure
	 *
	 * \note           the signature session should be considered invalid after failure, and should be freed immediately
	 *	 
	 */
	int wbcrypto_wbsm2_sign_stepA_withID(
		wbcrypto_wbsm2_public_key* pubkey,
		wbcrypto_wbsm2_private_key_segment* segmentA,
		wbcrypto_wbsm2_sign_session* sign_ctx,
		const char* id, size_t idlen,
		const unsigned char* msg, size_t msglen,
		int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
	);

	/**
	 * \brief           run the white box sm2 signature algorithm stepB,
	 *
	 * \param pubkey    the public key
	 *
	 * \param segmentB  the segmentB private key
	 *	 
	 * \param sign_ctx  the signature session
	 *
	 * \param f_rng     RNG function
	 *
	 * \param p_rng     RNG parameter
	 *
	 * \return          0 if successful, otherwise failure
	 *
	 * \note           the signature session should be considered invalid after failure, and should be freed immediately
	 *
	*/
	int wbcrypto_wbsm2_sign_stepB(
		wbcrypto_wbsm2_public_key* pubkey,
		wbcrypto_wbsm2_private_key_segment* segmentB,
		wbcrypto_wbsm2_sign_session* sign_ctx,
		int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
	);


	/**
	 * \brief            complete the white box sm2 signature algorithm,
	 *
	 * \param pubkey     the public key
	 *
	 * \param segmentA   the segmentA private key
	 *
	 * \param sign_ctx   the signature session
	 *
	 * \param sig        buffer for signature
	 *
	 * \param max_siglen the signature buffer size limit
	 *
	 * \param siglen     output param, for size of signature
	 *
	 * \return           0 if successful, otherwise failure
	 *
	 * \note             the signature session should be considered invalid after failure, and should be freed immediately
	 * 
	 */
	int wbcrypto_wbsm2_sign_complete(
		wbcrypto_wbsm2_public_key* pubkey,
		wbcrypto_wbsm2_private_key_segment* segmentA,
		wbcrypto_wbsm2_sign_session* sign_ctx,
		unsigned char* sig, size_t max_siglen, size_t* siglen
	);

	/**
	 * \brief           verify the sm2 signature with default userID,
	 *                      the result is encoded in ASN.1
	 *
	 * \param pubkey    the public key
	 *
	 * \param message   the message buffer
	 *
	 * \param msglen    the length of message
	 *
	 * \param sig      the signature buffer
	 *
	 * \param siglen   the length of signature
	 *
	 * \return          0 if successful, WBCRYPTO_ERR_SM2COOP_VERIFY_FAILED on signature mismatch, error otherwise
	 *
	 * \note            this is essentially a sm2 sig verify procedure, you can use a normal SM2 algorithm to do so instead of this
	 * 
	 */
	int wbcrypto_wbsm2_verify(
		wbcrypto_wbsm2_public_key* pubkey,
		const unsigned char* message, size_t msglen,
		const unsigned char* sig, size_t siglen
	);

	/**
	 * \brief           verify the sm2 signature with custom userID,
	 *                      the result is encoded in ASN.1
	 *
	 * \param pubkey    the public key
	 *
	 * \param id        the userID buffer
	 *
	 * \param idlen     the length of userID
	 *
	 * \param message   the message buffer
	 *
	 * \param msglen    the length of message
	 *
	 * \param sig      the signature buffer
	 *
	 * \param siglen   the length of signature
	 *
	 * \return          0 if successful, WBCRYPTO_ERR_SM2COOP_VERIFY_FAILED on signature mismatch, error otherwise
	 *
	 * \note            this is essentially a sm2 sig verify procedure, you can use a normal SM2 algorithm to do so instead of this
	 * 
	 */
	int wbcrypto_wbsm2_verify_withID(
		wbcrypto_wbsm2_public_key* pubkey,
		const unsigned char* id, size_t idlen,
		const unsigned char* msg, size_t msglen,
		const unsigned char* sig, size_t siglen
	);

#if defined(WBCRYPTO_SELF_TEST)
	int wbcrypto_wbsm2_self_test();
#endif

#ifdef __cplusplus
}
#endif

#endif /* wbsm2.h */
/**
 * \file sm2.h
 *
 * \brief This file contains the SM2 algorithm definitions and functions.
 *
 */
#ifndef WBCRYPTO_SM2_H
#define WBCRYPTO_SM2_H

#if !defined(WBCRYPTO_CONFIG_FILE)
#include "crypto/config.h"
#else
#include WBCRYPTO_CONFIG_FILE
#endif

#include "mbedtls/ecp.h"
#include "mbedtls/md.h"

#define WBCRYPTO_ERR_SM2_BAD_INPUT_DATA                    -0x0001  /**< Bad input parameters to function. */
#define WBCRYPTO_ERR_SM2_KEY_GEN_FAILED                    -0x0002  /**< Something failed during generation of a key. */
#define WBCRYPTO_ERR_SM2_KEY_CHECK_FAILED                  -0x0003  /**< Key failed to pass the library's validity check. */
#define WBCRYPTO_ERR_SM2_PUBLIC_FAILED                     -0x0004  /**< The public key operation failed. */
#define WBCRYPTO_ERR_SM2_PRIVATE_FAILED                    -0x0005  /**< The private key operation failed. */
#define WBCRYPTO_ERR_SM2_VERIFY_FAILED                     -0x0006  /**< The standard verification failed. */
#define WBCRYPTO_ERR_SM2_OUTPUT_TOO_LARGE                  -0x0007  /**< The output buffer for decryption is not large enough. */
#define WBCRYPTO_ERR_SM2_RNG_FAILED                        -0x0008  /**< The random generator failed to generate non-zeros. */
#define WBCRYPTO_ERR_SM2_ALLOC_FAILED                      -0x0009  /**< Failed to allocate memory. */
#define WBCRYPTO_ERR_SM2_DECRYPT_FAILED                    -0x000A  /**< The standard decrypt failed. */

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * \brief           The SM2 context structure, holds key to operate on
	 *
	 * \note            Please turn to ecp.h and mpi.h for value I/O
	 */
	typedef struct {
		mbedtls_ecp_group grp;      /*!< SHARED:  the curve to operate on         */
		mbedtls_mpi d;              /*!< PRIVATE: secret value                    */
		mbedtls_ecp_point Pb;       /*!< PUBLIC:  public value                    */
	} wbcrypto_sm2_context;

	/**
	 * \brief           This function will load the curve specified by SM2 Standard
	 *
	 * \note            This function will set the curve ID to MBEDTLS_ECP_DP_NONE
	 *
	 * \param grp       the group to load parameter into, MUST NOT be NULL
	 *
	 * \return          0 if successful, otherwise error
	 *                 
	 */
	int wbcrypto_sm2_load_default_group(mbedtls_ecp_group* grp);

	/**
	 * \brief           This function initializes the SM2 context
	 *
	 * \note            This function will initialize the context with default SM2 curve
	 *
	 * \param ctx       Context to initialize, MUST NOT be NULL
	 *
	 * \return          0 if successful,
	 *                  MBEDTLS_ERR_MPI_XXX if initialization failed
	 *                  
	 */
	int wbcrypto_sm2_context_init(wbcrypto_sm2_context* ctx);

	/**
	 * \brief          This function copies the components of an SM2 context.
	 *
	 * \param dst      The destination context. This must be initialized.
	 * \param src      The source context. This must be initialized.
	 *
	 * \return         \c 0 on success.
	 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory allocation failure.
	 */
	int wbcrypto_sm2_context_copy(wbcrypto_sm2_context* dst, const wbcrypto_sm2_context* src);

	/**
	 * \brief          This function frees the SM2 context.
	 *
	 * \param ctx      The context to free. May be \c NULL, in which case
	 *                 this function is a no-op. If it is not \c NULL, it must
	 *                 point to an initialized context.
	 */
	void wbcrypto_sm2_context_free(wbcrypto_sm2_context* ctx);


	/**
	 * \brief           Generate a SM2 keypair, given the group
	 *
	 * \param ctx       the SM2 context to put result in, must have a valid ECP group
	 *
	 * \param f_rng     RNG function  (we suggest using SM3 drbg for this function)
	 *
	 * \param p_rng     RNG parameter
	 *
	 * \return          0 if successful,
	 *                  or a MBEDTLS_ERR_ECP_XXX or MBEDTLS_MPI_XXX error code
	 */
	int wbcrypto_sm2_gen_keypair(
		wbcrypto_sm2_context* ctx, 
		int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
	);

	/**
	 * \brief           Validate that the private key is valid for this curve
	 *
	 * \param ctx       the sm2 context
	 *
	 * \return          0 if its valid,
	 *                  MBEDTLS_ERR_ECP_INVALID_KEY otherwise.
	 */
	int wbcrypto_sm2_check_privkey(wbcrypto_sm2_context* ctx);

	/**
	 * \brief           Validate that the public key is valid for this curve
	 *
	 * \param ctx       the sm2 context
	 *
	 * \return          0 if point is a valid private key,
	 *                  MBEDTLS_ERR_ECP_INVALID_KEY otherwise.
	 */
	int wbcrypto_sm2_check_pubkey(wbcrypto_sm2_context* ctx);


	/**
	 * \brief           run sm2 encryption algorithm, result is ASN.1 DER encoded
	 *						THIS IS THE RECOMMENDED ENCODING TO USE
	 *
	 * \param ctx       the sm2 context
	 *
	 * \param buffer    data to encrypt
	 *
	 * \param blen      data length
	 *
	 * \param out       buffer for ciphertext
	 *
	 * \param max_olen  buffer length limit for result
	 *
	 * \param olen      pointer to return the ciphertext length
	 *
	 * \param f_rng     RNG function
	 *
	 * \param p_rng     RNG parameter
	 *
	 * \return          0 if successful
	 *                  otherwise 
	 *					MBEDTLS_ERR_SM2_OUTPUT_TOO_LARGE,
	 *                  MBEDTLS_ERR_SM2_BAD_INPUT_DATA,MBEDTLS_ERR_SM2_ALLOC_FAILED
	 *                  ,MBEDTLS_ERR_ECP_XXX or MBEDTLS_ERR_MPI_XXX
	 *
	 * \note            according to GM/T 2009-2012, the ASN.1 of ciphertext is:
	 *                  SM2Cipher ::= SEQENCE(
	 *						XCoordinate INTEGER,
	 *						YCoordinate INTEGER,
	 * 						HASH        OCTET STRING SIZE(32),
	 *						CipherText  OCTET STRING
	 *					)
	 *
	 */
	int wbcrypto_sm2_encrypt_asn1(
		wbcrypto_sm2_context* ctx, 
		const unsigned char* buffer, size_t	blen,
		unsigned char* out, size_t max_olen, size_t* olen,
		int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
	);

	/**
	 * \brief           run the sm2 decrypt algorithm, the result is assumed to be ASN.1 DER encoded
	 *                      THIS IS THE RECOMMENDED ENCODING TO USE 
	                        see the corresponding encrypt function for encoding details
	 *
	 * \param ctx        the sm2 context
	 *
	 * \param ciphertext the ciphertext
	 *
	 * \param clen       the cipher byte length
	 *
	 * \param out        the plaintext output buffer
	 *
	 * \param max_olen   max capacity of the output buffer
	 *
	 * \param olen       pointer for returning plaintext length
	 *
	 * \return          0 if successful
	 *                  otherwise MBEDTLS_ERR_SM2_OUTPUT_TOO_LARGE,
	 *                  MBEDTLS_ERR_SM2_BAD_INPUT_DATA,MBEDTLS_ERR_SM2_ALLOC_FAILED
	 *                  ,MBEDTLS_ERR_ECP_XXX or MBEDTLS_ERR_MPI_XXX
	 */
	int wbcrypto_sm2_decrypt_asn1(
		wbcrypto_sm2_context* ctx, 
		const unsigned char* ciphertext, size_t clen,
		unsigned char* out, size_t max_olen, size_t* olen
	);


	/**
	 * \brief           run the sm2 signature algorithm, the result is encoded in ASN.1 DER
	 *                      THIS IS THE RECOMMENDED ENCODING TO USE
	 *
	 * \param ctx       the sm2 context
	 *
	 * \param msg      the message to sign
	 *
	 * \param msglen   the length of message
	 *
	 * \param out       signature output buffer
	 *
	 * \param max_olen  max buffer capacity of signature buffer
	 *
	 * \param olen      pointer for returned signature length
	 *
	 * \param f_rng     RNG function
	 *
	 * \param p_rng     RNG parameter
	 *
	 * \return          0 if successful
	 *                  otherwise MBEDTLS_ERR_SM2_OUTPUT_TOO_LARGE,
	 *                  MBEDTLS_ERR_SM2_BAD_INPUT_DATA,MBEDTLS_ERR_SM2_ALLOC_FAILED
	 *                  ,MBEDTLS_ERR_ECP_XXX or MBEDTLS_ERR_MPI_XXX
	 *
	 * \note            the encoding of signature in ASN.1 is:
	 *                  SM2 Signature::= (
	 *						R INTEGER,
	 *						S INTEGER
	 *					)
	 *					The length of R and S are 32Bytes, respectively
	 *
	 * \note           Currently we assume and only support SM3 as hash
	 *
	 * \note           Such encoding is only guranteed when using the standard curve parameter
	 *                     the length might not be 32Bytes if using other curve
	 */
	int wbcrypto_sm2_sign_asn1(
		wbcrypto_sm2_context* ctx,
		const unsigned char* msg, size_t msglen,
		unsigned char* out, size_t max_olen, size_t* olen,
		int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
	);

	/**
	 * \brief           verify the sm2 signature,
	 *                      the result is encoded in ASN.1
	 *                      THIS IS THE RECOMMENDED ENCODING TO USE
	 *
	 * \param ctx       the sm2 context
	 *
	 * \param msg       the message
	 *
	 * \param msglen    the length of message
	 *
	 * \param sig       the signature to verify
	 *
	 * \param siglen    the length of signature
	 *
	 * \return          0 if successful
	 *                  otherwise MBEDTLS_ERR_SM2_OUTPUT_TOO_LARGE,
	 *                  MBEDTLS_ERR_SM2_BAD_INPUT_DATA,MBEDTLS_ERR_SM2_ALLOC_FAILED
	 *                  ,MBEDTLS_ERR_ECP_XXX or MBEDTLS_ERR_MPI_XXX
	 */
	int wbcrypto_sm2_verify_asn1(
		wbcrypto_sm2_context* ctx, 
		const unsigned char* msg, size_t msglen,
		const unsigned char* sig, size_t siglen
	);


	/**
	 * \brief           run the sm2 signature algorithm with custom userID,
	 *                      the result is encoded as ASN.1 DER
	 *						see signature function with default userID for encoding details
	 *                      THIS IS THE RECOMMENDED ENCODING TO USE
	 *
	 * \param ctx       the sm2 context
	 *
	 * \param id        user ID, just a byte string
	 *
	 * \param idlen     id string length
	 *
	 * \param msg       the message to sign
	 *
	 * \param msglen    the length of message
	 *
	 * \param out       signature output buffer
	 *
	 * \param max_olen  max buffer capacity of signature buffer
	 *
	 * \param olen      pointer for returned signature length
	 *
	 * \param f_rng     RNG function
	 *
	 * \param p_rng     RNG parameter
	 *
	 * \return          0 if successful
	 *                  otherwise MBEDTLS_ERR_SM2_OUTPUT_TOO_LARGE,
	 *                  MBEDTLS_ERR_SM2_BAD_INPUT_DATA,MBEDTLS_ERR_SM2_ALLOC_FAILED
	 *                  ,MBEDTLS_ERR_ECP_XXX or MBEDTLS_ERR_MPI_XXX
	 *
	 */
	int wbcrypto_sm2_sign_withID_asn1(
		wbcrypto_sm2_context* ctx,
		const char* id, size_t idlen,
		const char* msg, size_t msglen,
		unsigned char* out, size_t max_olen, size_t* olen,
		int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
	);

	/**
	 *
	 * \brief           sm2 sign verify
	 *
	 * \param ctx       sm2 context
	 *
	 * \param id        user id such as user mail string
	 *
	 * \param idlen     id string length
	 *
	 * \param message   received message string
	 *
	 * \param msglen    messgae string length
	 *
	 * \param dgst      need to verify byte array (not hex string)
	 *                  onte: the buff are byte array ,them are not string
	 *                  if you input the string ,should transform the string to byte
	 *                  such as "120DEDF" is hex string, should make it to byte using the function you did
	 *                  hexString2byte.
	 *
	 * \param dgstlen   dgst byte array length
	 *
	 * \return          0 if successful
	 *                  otherwise MBEDTLS_ERR_SM2_OUTPUT_TOO_LARGE,
	 *                  MBEDTLS_ERR_SM2_BAD_INPUT_DATA,MBEDTLS_ERR_SM2_ALLOC_FAILED
	 *                  ,MBEDTLS_ERR_ECP_XXX or MBEDTLS_ERR_MPI_XXX
	 */
	int wbcrypto_sm2_verify_withID_asn1(
		wbcrypto_sm2_context* ctx, 
		const char* id, size_t idlen, 
		const char* msg, size_t msglen, 
		const unsigned char* sig, size_t siglen
	);




	/**
	 * \brief           run sm2 encryption algorithm, result is given as raw bytes
	 *
	 * \param ctx       the sm2 context
	 *
	 * \param buffer    data to encrypt
	 *
	 * \param blen      data length
	 *
	 * \param out       buffer for ciphertext
	 *
	 * \param max_out_len  buffer length limit for result
	 *
	 * \param olen      pointer to return the ciphertext length
	 *
	 * \param f_rng     RNG function
	 *
	 * \param p_rng     RNG parameter
	 *
	 * \return          0 if successful
	 *                  otherwise
	 *					MBEDTLS_ERR_SM2_OUTPUT_TOO_LARGE,
	 *                  MBEDTLS_ERR_SM2_BAD_INPUT_DATA,MBEDTLS_ERR_SM2_ALLOC_FAILED
	 *                  ,MBEDTLS_ERR_ECP_XXX or MBEDTLS_ERR_MPI_XXX
	 *
	 * \note            the ciphertext is encoded as C_1||C_2||C_3
	 *					C_1 is [1+32+32Bytes Long]
	 *                  C_2 is [Varying Bytes Long]
	 *                  C_3 is [32Bytes]
	 *
	 */
	int wbcrypto_sm2_encrypt_rawBytes(
		wbcrypto_sm2_context* ctx,
		const unsigned char* buffer, size_t	blen,
		unsigned char* out, size_t max_olen, size_t* olen,
		int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
	);

	/**
	 * \brief           run the sm2 decrypt algorithm, the result is assumed to be raw bytes
	 *                      see the corresponding encrypt function for encoding details
	 *
	 * \param ctx       the sm2 context
	 *
	 * \param cipher    the ciphertext
	 *
	 * \param clen      the cipher byte length
	 *
	 * \param out       the plaintext output buffer
	 *
	 * \param max_olen  max capacity of the output buffer
	 *
	 * \param olen      pointer for returned plaintext length
	 *
	 * \return          0 if successful
	 *                  otherwise MBEDTLS_ERR_SM2_OUTPUT_TOO_LARGE,
	 *                  MBEDTLS_ERR_SM2_BAD_INPUT_DATA,MBEDTLS_ERR_SM2_ALLOC_FAILED
	 *                  ,MBEDTLS_ERR_ECP_XXX or MBEDTLS_ERR_MPI_XXX
	 */
	int wbcrypto_sm2_decrypt_rawBytes(
		wbcrypto_sm2_context* ctx,
		const unsigned char* ciphertext, size_t clen,
		unsigned char* out, size_t max_olen, size_t* olen
	);


	/**
	 * \brief           run the sm2 signature algorithm, the result is encoded in rawBytes
	 *
	 * \param ctx       the sm2 context
	 *
	 * \param msg       the message to sign
	 *
	 * \param msglen    the length of message
	 *
	 * \param out       signature output buffer
	 *
	 * \param max_olen  max buffer capacity of signature buffer
	 *
	 * \param olen      pointer for returned signature length
	 *
	 * \param f_rng     RNG function
	 *
	 * \param p_rng     RNG parameter
	 *
	 * \return          0 if successful
	 *                  otherwise MBEDTLS_ERR_SM2_OUTPUT_TOO_LARGE,
	 *                  MBEDTLS_ERR_SM2_BAD_INPUT_DATA,MBEDTLS_ERR_SM2_ALLOC_FAILED
	 *                  ,MBEDTLS_ERR_ECP_XXX or MBEDTLS_ERR_MPI_XXX
	 *
	 * \note            we currently only support SM3 for hash
	 *
	 * \note            the length of encoding is actually bound to the bit length of curve, we only support the curve in the standard
	 *
	 * \note            the encoding of signature in rawBytes is:
	 *                      the concatenation of r and s, big-endian, 32Byte length each, of format mbedtls_mpi_write_binary
	 */
	int wbcrypto_sm2_sign_rawBytes(
		wbcrypto_sm2_context* ctx,
		const unsigned char* msg, size_t msglen,
		unsigned char* out, size_t max_olen, size_t* olen,
		int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
	);


	/**
	 * \brief           verify the sm2 signature,
	 *                      the result is encoded in rawBytes
	 *
	 * \param ctx       the sm2 context
	 *
	 * \param message   the message to verify
	 *
	 * \param msglen    the length of message
	 *
	 * \param sig       signature
	 *
	 * \param siglen    signature length
	 *
	 * \return          0 if successful
	 *                  otherwise MBEDTLS_ERR_SM2_OUTPUT_TOO_LARGE,
	 *                  MBEDTLS_ERR_SM2_BAD_INPUT_DATA,MBEDTLS_ERR_SM2_ALLOC_FAILED
	 *                  ,MBEDTLS_ERR_ECP_XXX or MBEDTLS_ERR_MPI_XXX
	 */
	int wbcrypto_sm2_verify_rawBytes(
		wbcrypto_sm2_context* ctx,
		const unsigned char* message, size_t msglen,
		const unsigned char* sig, size_t siglen
	);


	/**
	 * \brief           run the sm2 signature algorithm with custom userID,
	 *                      the result is encoded rawBytes
	 *                      see the wbcrypto_sm2_sign_rawBytes for encoding details
	 *
	 * \param ctx       the sm2 context
	 *
	 * \param id        user ID, just a byte string
	 *
	 * \param idlen     id string length
	 *
	 * \param message   the digest of message to sign
	 *
	 * \param msglen    the length of digest
	 *
	 * \param out       signature output buffer
	 *
	 * \param max_olen  max buffer capacity of signature buffer
	 *
	 * \param olen      pointer for returned signature length
	 *
	 * \param f_rng     RNG function
	 * \param p_rng     RNG parameter
	 *
	 * \return          0 if successful
	 *                  otherwise MBEDTLS_ERR_SM2_OUTPUT_TOO_LARGE,
	 *                  MBEDTLS_ERR_SM2_BAD_INPUT_DATA,MBEDTLS_ERR_SM2_ALLOC_FAILED
	 *                  ,MBEDTLS_ERR_ECP_XXX or MBEDTLS_ERR_MPI_XXX
	 *
	 */
	int wbcrypto_sm2_sign_withID_rawBytes(
		wbcrypto_sm2_context* ctx,
		const char* id, size_t idlen,
		const char* message, size_t msglen,
		unsigned char* out, size_t max_olen, size_t* olen,
		int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
	);

	/**
	 * \brief           verify the sm2 signature with custom userID,
	 *                      the result is encoded in rawBytes
	 *                      see the signature function for encoding details
	 *
	 * \param ctx       the sm2 context
	 *
	 * \param message   the message to verify
	 *
	 * \param msglen    the length of message
	 *
	 * \param sig       signature
	 *
	 * \param siglen    signature length
	 *
	 * \return          0 if successful, otherwise failure
	 */
	int wbcrypto_sm2_verify_withID_rawBytes(
		wbcrypto_sm2_context* ctx,
		const char* id, size_t idlen,
		const char* message, size_t msglen,
		const unsigned char* sig, size_t siglen
	);


	/**
	 * \brief           Internal function for SM2 Signature Algorithm
	 *					    this function computes the H(Z_a || M)
	 *                      see the standard for SM2, Part 2, Chapter 6 for details
	 *
	 * \param ctx       the sm2 context
	 *
	 * \param id        user id string
	 *
	 * \param idlen     id string length
	 *
	 * \param message   the message to sign
	 *
	 * \param msglen    message length
	 *
	 * \param out       result buffer, length must be able to hold SM3 result(32Bytes), also only use exactly that amount
	 *
	 * \return          0 if successful,otherwise failure
	 *
	 */
	int wbcrypto_sm2_compute_hashedMbar(
		wbcrypto_sm2_context* ctx,
		const unsigned char* id, size_t idlen,
		const unsigned char* message, size_t msglen,
		unsigned char* out
	);

#if defined(WBCRYPTO_SELF_TEST)
	/**
	 * \brief           sm2 test
	 *
	 * \param verbose   0 is nothing ;
	 *                  1 is test encrypt and decrypt;
	 *                  2 is test sign and verify
	 *
	 * @return          0 if successful
	 */
	int wbcrypto_sm2_self_test(int verbose);
#endif

#ifdef __cplusplus
}
#endif

#endif /* sm2.h */
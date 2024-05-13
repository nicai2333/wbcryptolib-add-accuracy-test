/**
 *
 * \file sm2coop.h
 *
 * \brief This file contains the SM2 cooperative algorithm definitions and functions.
 *
 */
#ifndef WBCRYPTO_SM2COOP_H
#define WBCRYPTO_SM2COOP_H

#if !defined(WBCRYPTO_CONFIG_FILE)
#include "crypto/config.h"
#else
#include WBCRYPTO_CONFIG_FILE
#endif

#include <stdint.h>
#include "mbedtls/ecp.h"
#include "crypto/adaptive_error.h"

#define WBCRYPTO_ERR_SM2COOP_GENERIC_FAILURE                   WBCRYPTO_ADAPT_ERROR(-0x0100)  /**< Unknown failure in this function. **/
#define WBCRYPTO_ERR_SM2COOP_ALLOC_FAILED                      WBCRYPTO_ADAPT_ERROR(-0x0101)  /**< Failed to allocate memory. */
#define WBCRYPTO_ERR_SM2COOP_INIT_FAILED                       WBCRYPTO_ADAPT_ERROR(-0x0102)  /**< Failed to run init function to a data struct */
#define WBCRYPTO_ERR_SM2COOP_BAD_INPUT_DATA                    WBCRYPTO_ADAPT_ERROR(-0x0103)  /**< Bad input parameters to function. */
#define WBCRYPTO_ERR_SM2COOP_INVALID_KEY                       WBCRYPTO_ADAPT_ERROR(-0x0104)  /**< Key failed to pass the library's validity check. */
#define WBCRYPTO_ERR_SM2COOP_OUTPUT_TOO_LARGE                  WBCRYPTO_ADAPT_ERROR(-0x0105)  /**< The output buffer for decryption is not large enough. */
#define WBCRYPTO_ERR_SM2COOP_RNG_FAILED                        WBCRYPTO_ADAPT_ERROR(-0x0106)  /**< The random generator failed to generate non-zeros. */
#define WBCRYPTO_ERR_SM2COOP_VERIFY_FAILED                     WBCRYPTO_ADAPT_ERROR(-0x0107)  /**< The standard verification failed. */

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * \brief           The SM2 Cooperative context structure, holds key to operate on
	 *
	 * \note            The server side and client side have the same key structure!
	 *
	 * \note            Please turn to ecp.h and mpi.h for value I/O
	 */
	typedef struct {
		mbedtls_ecp_group grp; /*!<  SHARED:  Elliptic curve and base point             */
		mbedtls_mpi hd;        /*!<  PRIVATE: The secret value                          */
		mbedtls_ecp_point W;   /*!<  PUBLIC:  The public key for signing                */
		mbedtls_ecp_point P;   /*!<  PUBLIC:  The public key for signature verification */
	} wbcrypto_sm2coop_context;

	/**
	 * \brief           This function will load the curve specified by SM2 Standard
	 *						note: the curve must be initialized with mbedtls_ecp_group_init()!
	 *
	 * \param grp       the group to load parameter into, MUST NOT be NULL
	 *
	 * \return          0 if successful, otherwise error
	 *
	 * \note            This function will set the curve ID to MBEDTLS_ECP_DP_NONE
	 *
	 */
	int wbcrypto_sm2coop_load_default_group(mbedtls_ecp_group* grp);

	/**
	 * \brief           This function initializes the SM2Coop context
	 *
	 * \param ctx       Context to initialize, MUST NOT be NULL
	 *
	 * \note            This function will NOT set the grp for you, consider setting it via load_default_group(&ctx)
	 * 
	 */
	void wbcrypto_sm2coop_context_init(wbcrypto_sm2coop_context* ctx);

	/**
	 * \brief          This function copies the components of an SM2Coop context.
	 *
	 * \param dst      The destination context. This must be initialized.
	 * 
	 * \param src      The source context. This must be initialized.
	 *
	 * \note           we will NOT COPY THE GROUP since this requires adding new curves to mbedtls, plz do it yourself
	 * 
	 * \return         0 on success, otherwise failure
	 * 
	 */
	int wbcrypto_sm2coop_context_copy(wbcrypto_sm2coop_context* dst, const wbcrypto_sm2coop_context* src);

	/**
	 * \brief          This function frees the SM2Coop context.
	 *
	 * \param ctx      The context to free. May be \c NULL, in which case
	 *                 this function is a no-op. If it is not \c NULL, it must
	 *                 point to an initialized context.
	 */
	void wbcrypto_sm2coop_context_free(wbcrypto_sm2coop_context* ctx);



	/**
	 * \brief           The SM2Coop Key Generation Protocol Session Context
	 *
	 * \note            The server side and client side have the same structure
	 *
	 * \note            Please turn to ecp.h and mpi.h for value I/O
	 */
	typedef struct {
		wbcrypto_sm2coop_context key; // the key to be created, get the key here after finishing the protocol
	} wbcrypto_sm2coop_keygen_session;

	/**
	 * \brief           This function initializes the keygen session
	 *
	 * \param ctx       Context to initialize, MUST NOT be NULL
	 *
	 * \note            This function will NOT set the grp in key for you, consider setting it via load_default_group(&key.grp)
	 *
	 */
	void wbcrypto_sm2coop_keygen_session_init(wbcrypto_sm2coop_keygen_session* ctx);

	/**
	 * \brief          This function copies the components of the keygen session.
	 *
	 * \param dst      The destination session. This must be initialized.
	 * 
	 * \param src      The source session. This must be initialized.
	 *
	 * \return         \c 0 on success, otherwise fail
	 */
	int wbcrypto_sm2coop_keygen_session_copy(wbcrypto_sm2coop_keygen_session* dst, const wbcrypto_sm2coop_keygen_session* src);

	/**
	 * \brief          This function frees the the keygen session.
	 *
	 * \param ctx      The session to free. May be \c NULL, in which case
	 *                 this function is a no-op. If it is not \c NULL, it must
	 *                 point to an initialized session.
	 */
	void wbcrypto_sm2coop_keygen_session_free(wbcrypto_sm2coop_keygen_session* ctx);


	/**
	 * \brief           start the key generation protocol, let the client send key to server
	 *
	 * \param ctx       the keygen session, MUST BE INITIALIZED & HAVE ITS KEY'S GRP SET
	 *
	 * \param client_w  the buffer to put the W to send to server, MUST NOT BE NULL
	 *
	 * \param max_client_w_len the size limit of the buffer
	 *
	 * \param client_w_len out param, tells the used size of client_w, MUST NOT BE NULL
	 *
	 * \param f_rng     the RNG function, MUST NOT BE NULL
	 *
	 * \param p_rng     the RNG context(1st arg of the function)
	 *
	 * \return          0 if success, otherwise fail
	 * 
	 * \note            the keygen session should be considered invalid after failure, and should be freed immediately
	 *
	 */
	int wbcrypto_sm2coop_keygen_client_send_key(
		wbcrypto_sm2coop_keygen_session* ctx,
		unsigned char* client_w, size_t max_client_w_len, size_t* client_w_len,
		int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
	);

	/**
	 * \brief           continue the key generation protocol,let the server receive client's key and respond with server's key
	 *					    THE PROTOCOL FOR SERVER COMPLETES AFTER THIS FUNCTION
	 *
	 * \param ctx       the keygen session, MUST BE INITIALIZED & HAVE ITS KEY'S GRP SET
	 *
	 * \param client_w  the buffer to read the W from client, MUST NOT BE NULL
	 *
	 * \param client_w_len the length of client_w
	 *
	 * \param server_w  the buffer to put the W to send to client, MUST NOT BE NULL
	 *
	 * \param max_server_w_len the size limit of the buffer
	 *
	 * \param server_w_len out param, tells the used size of server_w. MUST NOT BE NULL
	 *
	 * \param f_rng     the RNG function, MUST NOT BE NULL
	 *
	 * \param p_rng     the RNG context(1st arg of the function)
	 *
	 * \return          0 if success, otherwise fail
	 *
	 */
	int wbcrypto_sm2coop_keygen_server_exchange_key(
		wbcrypto_sm2coop_keygen_session* ctx,
		const unsigned char* client_w, size_t client_w_len,
		unsigned char* server_w, size_t max_server_w_len, size_t* server_w_len,
		int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
	);

	/**
	 * \brief           complete the key generation protocol,let the client receive server's key 
	 *					    THE PROTOCOL FOR CLIENT COMPLETES AFTER THIS FUNCTION
	 *
	 * \param ctx       the keygen session context, MUST NOT BE NULL, INITIALIZED, AND RAN client_send_key
	 *
	 * \param server_w  the w from server, MUST NOT BE NULL
	 *
	 * \param server_w_len the length of w
	 *
	 * \return          0 if success, otherwise fail
	 *
	 * \note            the keygen session context should be considered invalid after failure, and should be freed immediately
	 *
	 */
	int wbcrypto_sm2coop_keygen_client_receive_key(
		wbcrypto_sm2coop_keygen_session* ctx,
		const unsigned char* server_w, size_t server_w_len
	);



	/**
	 * \brief           run sm2coop encryption algorithm, result is ASN.1 DER encoded
	 *
	 * \param ctx       the sm2coop context, must have at least P and grp loaded
	 *
	 * \param buffer    data to encrypt, MUST NOT BE NULL
	 *
	 * \param blen      data length
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
	 * \note            this is essentially same as SM2 encryption algorithm
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
	int wbcrypto_sm2coop_encrypt(
		wbcrypto_sm2coop_context* ctx,
		const unsigned char* buffer, size_t	blen,
		unsigned char* out, size_t max_olen, size_t* olen,
		int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
	);



	/**
	 * \brief           The SM2Coop Decrypt protocol client session state
	 *					    offsets into the ciphertext to extract data without resolving ASN.1 again
	 */
	typedef struct {
		size_t total_size;
		mbedtls_ecp_point c1point;
		uint64_t c2_offset;
		uint64_t c2_len;
		uint64_t c3_offset;
		uint64_t c3_len;
	} wbcrypto_sm2coop_decrypt_client_session;

	/**
	 * \brief           This function initializes the decrypt context
	 *
	 * \param ctx       Context to initialize, MUST NOT be NULL
	 *
	 */
	void wbcrypto_sm2coop_decrypt_client_session_init(wbcrypto_sm2coop_decrypt_client_session* ctx);

	/**
	 * \brief          This function copies the components of the decrypt session.
	 *
	 * \param dst      The destination session. This must be initialized.
	 * \param src      The source session. This must be initialized.
	 *
	 * \return          0 if successful, otherwise failure
	 */
	int wbcrypto_sm2coop_decrypt_client_session_copy(
		wbcrypto_sm2coop_decrypt_client_session* dst,
		const wbcrypto_sm2coop_decrypt_client_session* src
	);

	/**
	 * \brief          This function frees the the decrypt session.
	 *
	 * \param ctx      The session to free. May be \c NULL, in which case
	 *                 this function is a no-op. If it is not \c NULL, it must
	 *                 point to an initialized session.
	 */
	void wbcrypto_sm2coop_decrypt_client_session_free(wbcrypto_sm2coop_decrypt_client_session* ctx);

	/**
	 * \brief           starts the sm2 decrypt protocol, the ciphertext is assumed to be ASN.1 DER encoded
	 *						see the corresponding encrypt function for encoding details
	 *
	 * \param ctx       the sm2coop context, must have at least hd, P and grp loaded 
	 *
	 * \param decrypt_ctx the extra session for decryption
	 *
	 * \param ciphertext    the ciphertext
	 *
	 * \param clen      the ciphertext byte length
	 *
	 * \param out       the request to send buffer
	 *
	 * \param max_olen  max capacity of the request buffer
	 *
	 * \param olen      pointer for returning request length
	 *
	 * \return          0 if successful, otherwise failure
	 *
	 * \note            the decrypt session context should be considered invalid after failure, and should be freed immediately
	 *
	 */
	int wbcrypto_sm2coop_decrypt_client_start(
		wbcrypto_sm2coop_context* ctx,
		wbcrypto_sm2coop_decrypt_client_session* decrypt_ctx,
		const unsigned char* ciphertext, size_t clen,
		unsigned char* out, size_t max_olen, size_t* olen
	);

	/**
	 * \brief           continue the decrypt protocol,let the server respond to request
	 *					    THE PROTOCOL FOR SERVER COMPLETES AFTER THIS FUNCTION
	 *
	 * \param ctx       the sm2coop context, must have at least hd and grp loaded 
	 *
	 * \param req       the buffer to put the request from client, MUST NOT BE NULL
	 *
	 * \param req_len   the length of request
	 *
	 * \param resp      the buffer to put response of server, MUST NOT BE NULL
	 *
	 * \param max_resplen the size limit of the response buffer
	 *
	 * \param resplen out param, tells the actual size of response, MUST NOT BE NULL
	 *
	 * \param f_rng     the RNG function, MUST NOT BE NULL
	 *
	 * \param p_rng     the RNG context(1st arg of the function)
	 *
	 * \return          0 if successful, otherwise failure
	 *
	 */
	int wbcrypto_sm2coop_decrypt_server_respond(
		wbcrypto_sm2coop_context* ctx,
		const unsigned char* req, size_t req_len,
		unsigned char* resp, size_t max_resplen, size_t* resplen,
		int(*f_rng)(void*, unsigned char*, size_t), void* p_rng
	);


	/**
	 * \brief           completes the sm2 decrypt protocol, the ciphertext is assumed to be ASN.1 DER encoded
	 *						see the corresponding encrypt function for encoding details
	 *						THE PROTOCOL FOR CLIENT COMPLETES AFTER THIS FUNCTION
	 *
	 * \param ctx       the sm2coop context, must have grp and hd loaded
	 *
	 * \param decrypt_ctx the extra context for decryption, MUST NOT BE NULL AND RAN client_start
	 *
	 * \param resp       the response, MUST NOT BE NULL
	 *
	 * \param resp_len   the response's length
	 *
	 * \param ciphertext the ciphertext, MUST NOT BE NULL
	 *
	 * \param clen       the ciphertext byte length
	 *
	 * \param out        the plaintext buffer, MUST NOT BE NULL
	 *
	 * \param max_olen   max capacity of the plaintext buffer
	 *
	 * \param olen       pointer for returning plaintext length, MUST NOT BE NULL
	 *
	 * \return           0 if successful, otherwise failure
	 *
	 * \note            the decrypt session context should be considered invalid after failure, and should be freed immediately
	 * 
	 */
	int wbcrypto_sm2coop_decrypt_client_complete(
		wbcrypto_sm2coop_context* ctx,
		wbcrypto_sm2coop_decrypt_client_session* decrypt_ctx,
		const unsigned char* resp, size_t resp_len,
		const unsigned char* ciphertext, size_t clen,
		unsigned char* out, size_t max_olen, size_t* olen
	);



	/**
	 * \brief           The SM2Coop signature client session
	 */
	typedef struct {
		mbedtls_mpi k;
	} wbcrypto_sm2coop_sign_client_session;

	/**
	 * \brief           This function initializes the signature session
	 *
	 * \param ctx       to initialize, MUST NOT be NULL
	 *
	 */
	void wbcrypto_sm2coop_sign_client_session_init(wbcrypto_sm2coop_sign_client_session* ctx);

	/**
	 * \brief          This function copies the components of the signature session.
	 *
	 * \param dst      The destination session. This must be initialized.
	 * \param src      The source session. This must be initialized.
	 *
	 * \return          0 if successful, otherwise failure
	 */
	int wbcrypto_sm2coop_sign_client_session_copy(
		wbcrypto_sm2coop_sign_client_session* dst,
		const wbcrypto_sm2coop_sign_client_session* src
	);

	/**
	 * \brief          This function frees the the signature session.
	 *
	 * \param ctx      The session to free. May be \c NULL, in which case
	 *                 this function is a no-op. If it is not \c NULL, it must
	 *                 point to an initialized session.
	 */
	void wbcrypto_sm2coop_sign_client_session_free(wbcrypto_sm2coop_sign_client_session* ctx);

	/**
	 * \brief           start the sm2coop signature algorithm, the result is encoded in ASN.1 DER
	 *
	 * \param ctx       the sm2coop context, must have hd, W, P, grp present
	 *
	 * \param sign_ctx  the sm2coop signature client session
	 *
	 * \param msg         the message to sign
	 *
	 * \param msglen      the length of message
	 *
	 * \param dgst      output buffer for the digest of message to sign
	 *
	 * \param max_dgstlen  max buffer capacity of digest buffer
	 *
	 * \param dgstlen   out param to collect the actual length of digest
	 *
	 * \param req      output buffer for the request to send to server
	 *
	 * \param max_reqlen  max buffer capacity of request buffer
	 *
	 * \param reqlen   out param to collect the actual length of request
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
	 */
	int wbcrypto_sm2coop_sign_client_start(
		wbcrypto_sm2coop_context* ctx,
		wbcrypto_sm2coop_sign_client_session* sign_ctx,
		const unsigned char* msg, size_t msglen,
		unsigned char* dgst, size_t max_dgstlen, size_t* dgstlen,
		unsigned char* req, size_t max_reqlen, size_t* reqlen,
		int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
	);

	/**
	 * \brief             run the sm2 signature algorithm with custom userID,
	 *                        the result is encoded as ASN.1 DER
	 *
	 * \param ctx         the sm2coop context, must have hd, W, P, grp present
	 *
	 * \param sign_ctx    the signature session state
	 *
	 * \param id          user ID, just a byte string
	 *
	 * \param idlen       id string length
	 *
	 * \param msg         the message to sign
	 *
	 * \param msglen      the length of message
	 *
	 * \param dgst        digest output buffer
	 *
	 * \param max_dgstlen  max buffer capacity of digest buffer
	 *
	 * \param dgstlen      pointer for returned digest length
	 * 
	 * \param req         request output buffer
	 *
	 * \param max_reqlen  max buffer capacity of request buffer
	 *
	 * \param reqlen      pointer for returned request length
	 *
	 * \param f_rng       RNG function
	 *
	 * \param p_rng       RNG parameter
	 *
	 * \return          0 if successful, otherwise failure
	 *
	 */
	int wbcrypto_sm2coop_sign_client_start_withID(
		wbcrypto_sm2coop_context* ctx,
		wbcrypto_sm2coop_sign_client_session* sign_ctx,
		const unsigned char* id, size_t idlen,
		const unsigned char* msg, size_t msglen,
		unsigned char* dgst, size_t max_dgstlen, size_t* dgstlen,
		unsigned char* req, size_t max_reqlen, size_t* reqlen,
		int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
	);

	/**
	 * \brief             respond the request of the sm2 signature algorithm,
	 *					    THE PROTOCOL FOR SERVER COMPLETES AFTER THIS FUNCTION
	 *					    
	 * \param ctx         the sm2coop context, must have hd, W, P, grp present
	 *
	 * \param dgst        digest input buffer
	 *
	 * \param dgst_len    size of digest
	 *
	 * \param req         request input buffer
	 *
	 * \param req_len     size of request
	 *
	 * \param resp        response output buffer
	 *
	 * \param max_resplen  max buffer capacity of response buffer
	 *
	 * \param resplen      pointer for returned response length
	 *
	 * \param f_rng       RNG function
	 *
	 * \param p_rng       RNG parameter
	 *
	 * \return          0 if successful, otherwise failure
	 *
	 */
	int wbcrypto_sm2coop_sign_server_respond(
		wbcrypto_sm2coop_context* ctx,
		const unsigned char* dgst, size_t dgst_len,
		const unsigned char* req, size_t req_len,
		unsigned char* resp, size_t max_resplen, size_t* resplen,
		int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
	);

	/**
	 * \brief             complete the sm2 signature algorithm,
	 *					    THE PROTOCOL FOR CLIENT COMPLETES AFTER THIS FUNCTION
	 *
	 * \param ctx         the sm2coop context, must have hd, W, P, grp present
	 *
	 * \param sign_ctx    the signature session state
	 *
	 * \param resp         response input buffer
	 *
	 * \param resplen     size of response
	 *
	 * \param sig        signature output buffer
	 *
	 * \param max_siglen  max buffer capacity of signature buffer
	 *
	 * \param siglen      pointer for returned signature length
	 *
	 * \return          0 if successful, otherwise failure
	 *
	 */
	int wbcrypto_sm2coop_sign_client_complete(
		wbcrypto_sm2coop_context* ctx,
		wbcrypto_sm2coop_sign_client_session* sign_ctx,
		const unsigned char* resp, size_t resplen,
		unsigned char* sig, size_t max_siglen, size_t* siglen
	);

	/**
	 * \brief           verify the sm2coop signature,
	 *                      the result is encoded in ASN.1
	 *
	 * \param ctx       the sm2coop context, must have P & grp present
	 *
	 * \param message   the message to verify
	 *
	 * \param msglen    the message length
	 *
	 * \param sig       the signature to verify
	 *
	 * \param siglen    signature length
	 *
	 * \return          0 if successful, otherwise failure
	 *
	 * \note            this is essentially same as sm2 signature verify
	 * 	 
	 */
	int wbcrypto_sm2coop_verify(
		wbcrypto_sm2coop_context* ctx,
		const unsigned char* message, size_t msglen,
		const unsigned char* sig, size_t siglen
	);

	/**
	 *
	 * \brief           verify SM2Coop signature
	 *
	 * \param ctx       the sm2coop context, must have P & grp present
	 *
	 * \param id        user id such as user mail string
	 *
	 * \param idlen     id string length
	 *
	 * \param msg       message
	 *
	 * \param msglen    message string length
	 *
	 * \param sig       the signature of data
	 *
	 * \param siglen    signature array length
	 *
	 * \return          0 if successful, otherwise failed
	 *
	 * \note            this is essentially same as sm2 signature verify
	 * 	 
	 */
	int wbcrypto_sm2coop_verify_withID(
		wbcrypto_sm2coop_context* ctx,
		const unsigned char* id, size_t idlen,
		const unsigned char* msg, size_t msglen,
		const unsigned char* sig, size_t siglen
	);

#if defined(WBCRYPTO_SELF_TEST)
	/**
	 * \brief           sm2coop self test
	 *
	 * \param verbose   0 is nothing ;
	 *                  1 is test encrypt and decrypt;
	 *                  2 is test sign and verify
	 *
	 * @return          0 if successful
	 */
	int wbcrypto_sm2coop_self_test(int verbose);
#endif

#ifdef __cplusplus
}
#endif

#endif /* sm2coop.h */
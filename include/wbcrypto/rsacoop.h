/**
 *
 * \file rsacoop.h
 *
 * \brief This file contains the RSA cooperative algorithm definitions and functions.
 *
 */
#ifndef WBCRYPTO_RSACOOP_H
#define WBCRYPTO_RSACOOP_H

#include <mbedtls/bignum.h>
#include <mbedtls/rsa.h>

/**
 * padding is MBEDTLS_RSA_PKCS_V15
 */

#define WBCRYPTO_ERR_RSACOOP_BAD_INPUT_DATA    -0X0201		 /**< Bad input parameters to function. */
#define WBCRYPTO_ERR_RSACOOP_ALLOC_FAILED      -0X0202	     /**< alloc() failed */
#define WBCRYPTO_ERR_RSACOOP_OUTPUT_TOO_LARGE  -0x0203       /**< output is longer than buffer*/
#define WBCRYPTO_ERR_RSACOOP_INIT_FAILED       -0X0204		 /**< cannot init struct */
#define WBCRYPTO_ERR_RSACOOP_KEY_GEN_FAILED    -0x0205		 /**< Something failed during generation of a key. */
#define WBCRYPTO_ERR_RSACOOP_VERIFY_FAILED     -0x0206       /**< signature verify failed. */

#ifdef __cplusplus
extern "C"
{
#endif

	/**
	 * \brief           The RSA Cooperative context structure, holds the client shard of key
	 *
	 * \note            Please turn to ecp.h and mpi.h for value I/O
	 *
	 */
	typedef struct {
		mbedtls_rsa_context pk; // PUBLIC: public key of the coop key
		mbedtls_mpi hd_A;       // PRIVATE
		mbedtls_mpi hd_SA;      // PRIVATE
		mbedtls_mpi n_A;        // PRIVATE
	} wbcrypto_rsacoop_client_context;

	/**
	 * \brief           This function initializes the context
	 *
	 * \param ctx       Context to initialize, MUST NOT be NULL
	 *
	 */
	void wbcrypto_rsacoop_client_context_init(wbcrypto_rsacoop_client_context* ctx);

	/**
	 * \brief          This function frees the context.
	 *
	 * \param ctx      The context to free. May be \c NULL, in which case
	 *                 this function is a no-op. If it is not \c NULL, it must
	 *                 point to an initialized context.
	 */
	void wbcrypto_rsacoop_client_context_free(wbcrypto_rsacoop_client_context* ctx);


	/**
	 * \brief           The RSA Cooperative context structure, holds the server shard of key
	 */
	typedef struct {
		mbedtls_rsa_context client_pk; // PUBLIC : public key of the coop key
		mbedtls_rsa_context keypair;   // PRIVATE: RSA public and private key of server
	} wbcrypto_rsacoop_server_context;

	/**
	 * \brief           This function initializes the context
	 *
	 * \param ctx       Context to initialize, MUST NOT be NULL
	 *
	 */
	void wbcrypto_rsacoop_server_context_init(wbcrypto_rsacoop_server_context* ctx);

	/**
	 * \brief          This function frees the context.
	 *
	 * \param ctx      The context to free. May be \c NULL, in which case
	 *                 this function is a no-op. If it is not \c NULL, it must
	 *                 point to an initialized context.
	 */
	void wbcrypto_rsacoop_server_context_free(wbcrypto_rsacoop_server_context* ctx);



	/**
	* \brief           The RSACoop Key generation Protocol Session for client
	*/
	typedef struct {
		mbedtls_mpi d_SA;                     // transient value
		mbedtls_rsa_context tmp_keypair;      // the transient keypair present for protocol
		wbcrypto_rsacoop_client_context key;  // the result key, use extract_key() to get it after complete
	} wbcrypto_rsacoop_keygen_client_session;

	/**
	 * \brief           This function initializes the session
	 *
	 * \param ctx       Session to initialize, MUST NOT be NULL
	 *
	 */
	void wbcrypto_rsacoop_keygen_client_session_init(wbcrypto_rsacoop_keygen_client_session* ctx);

	/**
	 * \brief          This function frees the session.
	 *
	 * \param ctx      The session to free. May be \c NULL, in which case
	 *                 this function is a no-op. If it is not \c NULL, it must
	 *                 point to an initialized session.
	 */
	void wbcrypto_rsacoop_keygen_client_session_free(wbcrypto_rsacoop_keygen_client_session* ctx);


	/**
	* \brief           The RSACoop Key generation Protocol Session for server
	*/
	typedef struct {
		wbcrypto_rsacoop_server_context key; //get your key here after finishing the protocol
	} wbcrypto_rsacoop_keygen_server_session;

	/**
	 * \brief           This function initializes the session
	 *
	 * \param ctx       Session to initialize, MUST NOT be NULL
	 *
	 */
	void wbcrypto_rsacoop_keygen_server_session_init(wbcrypto_rsacoop_keygen_server_session* ctx);

	/**
	 * \brief          This function frees the session.
	 *
	 * \param ctx      The session to free. May be \c NULL, in which case
	 *                 this function is a no-op. If it is not \c NULL, it must
	 *                 point to an initialized session.
	 */
	void wbcrypto_rsacoop_keygen_server_session_free(wbcrypto_rsacoop_keygen_server_session* ctx);


	/**
	 * \brief            client-side function, start the key generation protocol
	 *
	 * \param client     the context
	 *
	 * \param nbits      the bit length of result RSA key, 2048 is a good candidate
	 *
	 * \param exponent   the public exponent, 65537 is a good candidate
	 *
	 * \param req        request buffer
	 *
	 * \param max_reqlen the request buffer's total size
	 *
	 * \param reqlen     out param, tells how much of req is used
	 *
	 * \param f_rng      random function, see mbedtls for detail
	 *
	 * \param p_rng      context of random function
	 *
	 * \return           opcode, 0 for success, other is failure
	 *
	 */
	int wbcrypto_rsacoop_keygen_client_start(
		wbcrypto_rsacoop_keygen_client_session* client,
		int nbits, int exponent,
		unsigned char* req, size_t max_reqlen, size_t* reqlen,
		int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
	);

	/**
	 * \brief              server-side function, complete the server side and respond to client side
	 *
	 * \param server       the context
	 *
	 * \param nbits        the bit length of result RSA key, 2048 is a good candidate
	 *
	 * \param exponent     the public exponent, 65537 is a good candidate
	 *
	 * \param req          request buffer
	 *
	 * \param reqlen       the length of request
	 *
	 * \param resp         response buffer
	 *
	 * \param max_resplen  the response buffer's total size
	 *
	 * \param reqlen       out param, tells how much of resp is used
	 *
	 * \param f_rng        random function, see mbedtls for detail
	 *
	 * \param p_rng        context of random function
	 *
	 * \return             opcode, 0 for success, other is failure
	 *
	 */
	int wbcrypto_rsacoop_keygen_server_respond(
		wbcrypto_rsacoop_keygen_server_session* server,
		int nbits, int exponent,
		unsigned char* req, size_t req_len,
		unsigned char* resp, size_t max_resplen, size_t* resplen,
		int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
	);

	/**
	 * \brief            client-side function, complete the key generation protocol
	 *
	 * \param client     the context
	 *
	 * \param resp       response buffer
	 *
	 * \param resp_len   response length
	 *
	 * \return           opcode, 0 for success, other is failure
	 *
	 */
	int wbcrypto_rsacoop_keygen_client_complete(
		wbcrypto_rsacoop_keygen_client_session* client,
		unsigned char* resp, size_t resp_len
	);

	/**
	 * \brief            after complete, extract the key from context
	 *
	 * \param ctx        the context to hold the key
	 *
	 * \param keygen_ctx completed keygen context
	 *
	 * \note             this function IS NOT IDEMPOTENT, YOU CAN ONLY CALL THIS ONCE on a keygen_ctx!
	 *
	 * \return           opcode, 0 for success, other is failure
	 *
	 */
	int wbcrypto_rsacoop_keygen_client_extract_key(
		wbcrypto_rsacoop_client_context* ctx,
		wbcrypto_rsacoop_keygen_client_session* keygen_ctx
	);

	/**
	 * \brief            after complete, extract the key from context
	 *
	 * \param ctx        the context to hold the key
	 *
	 * \param keygen_ctx completed keygen context
	 *
	 * \note             this function IS NOT IDEMPOTENT, YOU CAN ONLY CALL THIS ONCE on a keygen_ctx!
	 *
	 * \return           opcode, 0 for success, other is failure
	 *
	 */
	int wbcrypto_rsacoop_keygen_server_extract_key(
		wbcrypto_rsacoop_server_context* ctx,
		wbcrypto_rsacoop_keygen_server_session* keygen_ctx
	);


	/**
	 * \brief             client-side function, start the signature protocol
	 *
	 * \param client      the context
	 *
	 * \param md_alg      the type of digest to use
	 *
	 * \param msg         the message to digest
	 *
	 * \param msglen      the length of message to digest
	 *
	 * \param dgst        the digest buffer, to send to server
	 *
	 * \param max_dgstlen the digest buffer's total size
	 *
	 * \param dgstlen     out param, tells how much of digest is used
	 *
	 * \param req         the request buffer, to send to server
	 *
	 * \param max_reqlen  the request buffer's total size
	 *
	 * \param reqlen      out param, tells how much of request is used
	 *
	 * \return            opcode, 0 for success, other is failure
	 *
	 */
	int wbcrypto_rsacoop_sign_client_start(
		wbcrypto_rsacoop_client_context* client,
		const mbedtls_md_info_t* md_alg,
		const unsigned char* msg, size_t msglen,
		unsigned char* dgst, size_t max_dgstlen, size_t* dgstlen,
		unsigned char* req, size_t max_reqlen, size_t* reqlen
	);

	/**
	 * \brief             server-side function, respond to the signature protocol
	 *
	 * \param server      the context
	 *
	 * \param dgst        the digest buffer
	 *
	 * \param dgstlen     the length of digest
	 *
	 * \param req         the request buffer
	 *
	 * \param reqlen      the length of request
	 *
	 * \param resp        the response buffer, to send to server
	 *
	 * \param max_resplen the response buffer's total size
	 *
	 * \param resplen     out param, tells how much of resp is used
	 *
	 * \return            opcode, 0 for success, other is failure
	 *
	 */
	int wbcrypto_rsacoop_sign_server_respond(
		wbcrypto_rsacoop_server_context* server,
		unsigned char* dgst, size_t dgstlen,
		unsigned char* req, size_t reqlen,
		unsigned char* resp, size_t max_resplen, size_t* resplen
	);

	/**
	 * \brief              client-side function, complete the signing protocol
	 *
	 * \param client       the context
	 *
	 * \param resp         response buffer
	 *
	 * \param resp_len     response length
	 *
	 * \param sig          signature buffer
	 *
	 * \param max_siglen   the signature buffer's total size
	 *
	 * \param siglen       out param, tells how much of sig is used
	 *
	 * \return             opcode, 0 for success, other is failure
	 *
	 */
	int wbcrypto_rsacoop_sign_client_complete(
		wbcrypto_rsacoop_client_context* client,
		unsigned char* resp, size_t resp_len,
		unsigned char* sig, size_t max_siglen, size_t* siglen
	);

	/**
	 * \brief            verify the signature
	 *
	 * \param pubkey     the public key of coop key
	 *
	 * \param md_alg     the type of digest used in signature        
	 *
	 * \param msg        the message signed by signature
	 *
	 * \param msg_len    the length of message
	 *
	 * \param sig        the signature
	 *
	 * \param sig_len    the length of signature
	 *
	 * \return           opcode, 0 for success, other is failure
	 *
	 */
	int wbcrypto_rsacoop_verify(
		mbedtls_rsa_context* pubkey,
		const mbedtls_md_info_t* md_alg,
		const unsigned char* msg, size_t msg_len, 
		const unsigned char* sig, size_t sig_len
	);


#if defined(WBCRYPTO_SELF_TEST)
	int rsa_cloud_self_test(int v);
#endif

#ifdef __cplusplus
}
#endif

#endif /* rsacoop.h */
#ifndef WBCRYPTO_ECDSACOOP_H
#define WBCRYPTO_ECDSACOOP_H

#if !defined(WBCRYPTO_CONFIG_FILE)
#include "crypto/config.h"
#else
#include WBCRYPTO_CONFIG_FILE
#endif

#include "mbedtls/ecp.h"

#define PRIME_BITE_SIZE 1024

#define WBCRYPTO_ERR_ECDSA_COOP_INIT_FAILED                    -0x0110 /**< Bad input parameters to function. */
#define WBCRYPTO_ERR_ECDSA_COOP_OUTPUT_TOO_LARGE                  -0x0117  /**< The output buffer for decryption is not large enough. */

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct
    {
        mbedtls_ecp_group grp; /*!<  SHARED:  Elliptic curve and base point             */
        mbedtls_mpi N;         // N = p1 * p2
        mbedtls_mpi g;         // g = N + 1
        mbedtls_mpi N_2;       // N = N ^ 2
    } wbcrypto_ecdsa_coop_common;

    typedef struct
    {
        wbcrypto_ecdsa_coop_common common;
        mbedtls_mpi u;     // L(g,lamda,N^2,N)
        mbedtls_mpi lamda; // lcm(p1-1,p2-1)
        mbedtls_mpi k;
        mbedtls_ecp_point R; // R = k*G
        mbedtls_mpi x;
    } wbcrypto_ecdsa_coop_client_context;

    typedef struct
    {
        wbcrypto_ecdsa_coop_common common;
        mbedtls_mpi x;
        mbedtls_mpi k;
        mbedtls_mpi ex;
        mbedtls_mpi otx;
        mbedtls_mpi ek;
    } wbcrypto_ecdsa_coop_server_context;


    /**
	 * \brief           The SM2Coop Key Generation Protocol Context
	 *
	 * \note            The server side and client side have the same structure
	 *
	 * \note            Please turn to ecp.h and mpi.h for value I/O
	 */
	typedef struct {
		wbcrypto_ecdsa_coop_client_context key; // the key to be created, get the key here after finishing the protocol
	} wbcrypto_ecdsa_coop_keygen_client_context;


    /**
	 * \brief           The SM2Coop Key Generation Protocol Context
	 *
	 * \note            The server side and client side have the same structure
	 *
	 * \note            Please turn to ecp.h and mpi.h for value I/O
	 */
	typedef struct {
		wbcrypto_ecdsa_coop_server_context key; // the key to be created, get the key here after finishing the protocol
	} wbcrypto_ecdsa_coop_keygen_server_context;

  
    /*client*/
    int wbcrypto_ecdsa_coop_client_context_init(wbcrypto_ecdsa_coop_client_context *ctx, int grp_id);
    void wbcrypto_ecdsa_coop_client_context_free(wbcrypto_ecdsa_coop_client_context *ctx);

    /* generate g N N^2 etc.*/
    int wbcrypto_ecdsa_coop_client_gen_params(wbcrypto_ecdsa_coop_client_context *ctx, int (*f_rng)(void *, unsigned char *, size_t),
                                              void *p_rng);
                                              
    int wbcrypto_ecdsa_coop_keygen_client_context_init(wbcrypto_ecdsa_coop_keygen_client_context* ctx, int grp_id);

    int wbcrypto_ecdsa_coop_keygen_server_context_init(wbcrypto_ecdsa_coop_keygen_server_context* ctx, int grp_id);

                                              

    /*generate ek and then send to server*/
    int wbcrypto_ecdsa_coop_client_gen_ek(wbcrypto_ecdsa_coop_client_context *ctx, mbedtls_mpi *ek,
                                          int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
    /*generate Pk*/
    int wbcrypto_ecdsa_coop_client_gen_Pk(wbcrypto_ecdsa_coop_client_context *ctx, const mbedtls_ecp_point *Ps, mbedtls_ecp_point *Pk);

    /*client signature*/
    int wbcrypto_ecdsa_coop_client_sign(wbcrypto_ecdsa_coop_client_context *ctx,
                                        const mbedtls_mpi *ex, const mbedtls_mpi *ps,
                                        const mbedtls_mpi *r, mbedtls_mpi *s);

    /*client precompute*/
    int wbcrypto_ecdsa_coop_client_precompute(wbcrypto_ecdsa_coop_client_context *ctx,
                                              int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);

    /*server*/
    int wbcrypto_ecdsa_coop_server_context_init(wbcrypto_ecdsa_coop_server_context *ctx, int grp_id);
    void wbcrypto_ecdsa_coop_server_context_free(wbcrypto_ecdsa_coop_server_context *ctx);
    /* generate ek,k etc.*/
    int wbcrypto_ecdsa_coop_server_gen_params(wbcrypto_ecdsa_coop_server_context *ctx,
                                              const wbcrypto_ecdsa_coop_common *ccom,
                                              const mbedtls_mpi *ek,
                                              int (*f_rng)(void *, unsigned char *, size_t),
                                              void *p_rng);
    /* generate ek,k from raw params */
    int wbcrypto_ecdsa_coop_server_gen_raw_params(wbcrypto_ecdsa_coop_server_context *ctx,
                                          const mbedtls_mpi *g,
                                          const mbedtls_mpi *N,
                                          const mbedtls_mpi *N_2,
                                          const mbedtls_mpi *ek,
                                          int (*f_rng)(void *, unsigned char *, size_t),
                                          void *p_rng);
                                
    /*generate Ps*/
    int wbcrypto_ecdsa_coop_server_gen_Ps(wbcrypto_ecdsa_coop_server_context *ctx, mbedtls_ecp_point *Ps,
                                          int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);

    /*server signature*/
    int wbcrypto_ecdsa_coop_server_sign(wbcrypto_ecdsa_coop_server_context *ctx, const mbedtls_ecp_point *Ra, const mbedtls_mpi *h, mbedtls_mpi *ps, mbedtls_mpi *r,
                                        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);

    /*server precompute*/
    int wbcrypto_ecdsa_coop_server_precompute(wbcrypto_ecdsa_coop_server_context *ctx,
                                              int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);

    // verify signature
    int wbcrypto_ecdsa_coop_verify_sign(mbedtls_ecp_group *grp,
                                        const unsigned char *hash_msg, size_t hash_len,
                                        const mbedtls_ecp_point *Pk,
                                        const mbedtls_mpi *r,
                                        const mbedtls_mpi *s);



    // TEST
    int test_ecdsa_coop_scheme(mbedtls_mpi *rr, mbedtls_mpi *ss,
                               const unsigned char *hash_msg, size_t hash_len,
                               int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);



    int wbcrypto_ecdsa_coop_keygen_client_send_key(
	wbcrypto_ecdsa_coop_keygen_client_context* ctx,
	unsigned char* client_parm, size_t max_client_parm_len, size_t* client_parm_len,
	int (*f_rng)(void*, unsigned char*, size_t), void* p_rng);

    
    int wbcrypto_ecdsa_coop_keygen_server_exchange_key(
	wbcrypto_ecdsa_coop_keygen_server_context* ctx,
	const unsigned char* client_param, size_t client_param_len,
	unsigned char* server_Ps, size_t max_server_Ps_len, size_t* server_Ps_len,
	int (*f_rng)(void*, unsigned char*, size_t), void* p_rng);

    int wbcrypto_ecdsa_coop_keygen_client_receive_key(
	wbcrypto_ecdsa_coop_keygen_client_context* ctx,
	const unsigned char* server_Ps, size_t server_Ps_len);

    int wbcrypto_ecdsa_coop_sign_client_start(
    wbcrypto_ecdsa_coop_client_context *ctx,
    const unsigned char *msg, size_t msglen,
    unsigned char *dgst, size_t max_dgstlen,
    size_t* dgstlen, unsigned char* req, size_t max_reqlen, size_t* reqlen,
    int (*f_rng)(void*, unsigned char*, size_t), void* p_rng);

    int wbcrypto_ecdsa_coop_sign_server_respond(
	wbcrypto_ecdsa_coop_server_context* ctx,
	const unsigned char* dgst, size_t dgst_len,
	const unsigned char* req, size_t req_len,
	unsigned char* resp, size_t max_resplen, size_t* resplen,
	int (*f_rng)(void*, unsigned char*, size_t), void* p_rng);
    
    int wbcrypto_ecdsa_coop_sign_client_complete(
	wbcrypto_ecdsa_coop_client_context* ctx,
	unsigned char* resp, size_t resplen,
	unsigned char* sig, size_t max_siglen, size_t* siglen,
	int (*f_rng)(void*, unsigned char*, size_t), void* p_rng);






#ifdef __cplusplus
}
#endif // C++

#endif /* ecdsacoop.h */
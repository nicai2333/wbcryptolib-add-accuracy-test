#include <ctype.h>
#include <memory.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "wbcrypto/ecdsacoop.h"
#include "hex_utils.h"
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>


int test_keygen(wbcrypto_ecdsa_coop_client_context* client_key, wbcrypto_ecdsa_coop_server_context* server_key) {
	int ret = 0;
	char client_params[1024] = { 0 };
	size_t client_params_len = 0;
	char server_Ps[1024] = { 0 };
	size_t server_Ps_len = 0;
	mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;

	
	wbcrypto_ecdsa_coop_keygen_client_context client;
    wbcrypto_ecdsa_coop_keygen_server_context server;

	mbedtls_ctr_drbg_init( &ctr_drbg );
	mbedtls_entropy_init( &entropy );
    const char *pers = "ecdsa_genkey";

	wbcrypto_ecdsa_coop_keygen_client_context_init(&client, server_key->common.grp.id);

	wbcrypto_ecdsa_coop_keygen_server_context_init(&server,server_key->common.grp.id);

    
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                                       (const unsigned char *) pers,
                                       strlen( pers ) ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
    }


    unsigned char hash_msg[9] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09};
    mbedtls_mpi rr;
    mbedtls_mpi ss;

    mbedtls_mpi_init(&rr);
    mbedtls_mpi_init(&ss);

	
		MBEDTLS_MPI_CHK(wbcrypto_ecdsa_coop_keygen_client_send_key(
		&client,
		client_params, sizeof(client_params), &client_params_len,
		mbedtls_ctr_drbg_random, &ctr_drbg
	));


	MBEDTLS_MPI_CHK(wbcrypto_ecdsa_coop_keygen_server_exchange_key(
		&server,
		client_params, client_params_len,
		server_Ps, sizeof(server_Ps),&server_Ps_len,
		mbedtls_ctr_drbg_random, &ctr_drbg
	));

	MBEDTLS_MPI_CHK(wbcrypto_ecdsa_coop_keygen_client_receive_key(
		&client,
		server_Ps, &server_Ps_len
	));

// 	MBEDTLS_MPI_CHK(wbcrypto_sm2coop_context_copy(client_key, &client.key));
// 	MBEDTLS_MPI_CHK(wbcrypto_sm2coop_context_copy(server_key, &server.key));

// cleanup:
// 	wbcrypto_sm2coop_keygen_context_free(&client);
// 	wbcrypto_sm2coop_keygen_context_free(&server);
// 	return ret;

	cleanup:
	return ret;
}

// int test_encrypt_decrypt(wbcrypto_ecdsa_coop_client_context* client, wbcrypto_ecdsa_coop_server_context* server) {
// 	int ret = 0;
// 	char plaintext_buf[] = "encryption standard";
// 	char ciphertext_buf[1024] = { 0 };
// 	size_t ciphertext_len = 0;
// 	char client_request_buf[1024] = { 0 };
// 	size_t client_request_len = 0;
// 	char server_response_buf[1024] = { 0 };
// 	size_t server_response_len = 0;
// 	char decrypted_buf[1024] = { 0 };
// 	size_t decrypted_len = 0;

// 	wbcrypto_sm2coop_decrypt_client_context decrypt_ctx;
// 	wbcrypto_sm2coop_decrypt_client_context_init(&decrypt_ctx);

// 	MBEDTLS_MPI_CHK(wbcrypto_sm2coop_encrypt(
// 		client,
// 		plaintext_buf, sizeof(plaintext_buf)-1,
// 		ciphertext_buf, sizeof(ciphertext_buf), &ciphertext_len,
// 		mock_rand_hex, rand_value
// 	));

// 	MBEDTLS_MPI_CHK(wbcrypto_sm2coop_decrypt_client_start(
// 		client,
// 		&decrypt_ctx,
// 		ciphertext_buf, ciphertext_len,
// 		client_request_buf, sizeof(client_request_buf), &client_request_len
// 	));

// 	MBEDTLS_MPI_CHK(wbcrypto_sm2coop_decrypt_server_respond(
// 		server,
// 		client_request_buf, client_request_len,
// 		server_response_buf, sizeof(server_response_buf), &server_response_len,
// 		mock_rand_hex, rand_value
// 	));

// 	MBEDTLS_MPI_CHK(wbcrypto_sm2coop_decrypt_client_complete(
// 		client, &decrypt_ctx,
// 		server_response_buf, server_response_len,
// 		ciphertext_buf, ciphertext_len,
// 		decrypted_buf, sizeof(decrypted_buf), &decrypted_len
// 	));

// 	MBEDTLS_MPI_CHK(strncmp(decrypted_buf, plaintext_buf, sizeof(plaintext_buf)-1));

// cleanup:
// 	wbcrypto_sm2coop_decrypt_client_context_free(&decrypt_ctx);
// 	return ret;
// }

// int test_sign_verify(wbcrypto_ecdsa_coop_client_context* client, wbcrypto_ecdsa_coop_server_context* server) {
// 	int ret = 0;
// 	char msg_buf[] = "signature standard";
// 	char sig_buf[1024] = { 0 };
// 	size_t sig_len = 0;
// 	char dgst_buf[1024] = { 0 };
// 	size_t dgst_len = 0;
// 	char req_buf[1024] = { 0 };
// 	size_t req_len = 0;
// 	char resp_buf[1024] = { 0 };
// 	size_t resp_len = 0;

// 	wbcrypto_ecdsa_coop_client_context sign_ctx;
// 	wbcrypto_sm2coop_sign_client_context_init(&sign_ctx);

// 	MBEDTLS_MPI_CHK(wbcrypto_sm2coop_sign_client_start(
// 		client,
// 		&sign_ctx,
// 		msg_buf, sizeof(msg_buf)-1,
// 		dgst_buf, sizeof(dgst_buf), &dgst_len,
// 		req_buf, sizeof(req_buf), &req_len,
// 		mock_rand_hex, rand_value
// 	));

// 	MBEDTLS_MPI_CHK(wbcrypto_sm2coop_sign_server_respond(
// 		server,
// 		dgst_buf, dgst_len,
// 		req_buf, req_len,
// 		resp_buf, sizeof(resp_buf), &resp_len,
// 		mock_rand_hex, rand_value
// 	));

// 	MBEDTLS_MPI_CHK(wbcrypto_sm2coop_sign_client_complete(
// 		client,
// 		&sign_ctx,
// 		resp_buf, resp_len,
// 		sig_buf, sizeof(sig_buf), &sig_len,
// 		mock_rand_hex, rand_value
// 	));

// 	MBEDTLS_MPI_CHK(wbcrypto_sm2coop_verify(
// 		client,
// 		msg_buf, sizeof(msg_buf) - 1,
// 		sig_buf, sig_len
// 	));

// cleanup:
// 	wbcrypto_sm2coop_sign_client_context_free(&sign_ctx);
// 	return ret;
// }

int main() {

	int ret = 0;
	wbcrypto_ecdsa_coop_client_context client;
    wbcrypto_ecdsa_coop_server_context server;
	wbcrypto_ecdsa_coop_client_context_init(&client, MBEDTLS_ECP_DP_SECP256R1);
	wbcrypto_ecdsa_coop_server_context_init(&server, MBEDTLS_ECP_DP_SECP256R1);

    unsigned char hash_msg[9] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09};
	MBEDTLS_MPI_CHK(test_keygen(&client, &server));
	 mbedtls_mpi rr;
	 mbedtls_mpi ss;

	 mbedtls_mpi_init(&rr);
	 mbedtls_mpi_init(&ss);


     mbedtls_ctr_drbg_context ctr_drbg;
     mbedtls_entropy_context entropy;

     mbedtls_ctr_drbg_init( &ctr_drbg );

     const char *pers = "rsa_genkey";

     mbedtls_entropy_init( &entropy );
     if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                                        (const unsigned char *) pers,
                                        strlen( pers ) ) ) != 0 )
     {
         printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
     }

//    char client_params[1024] = { 0 };
//    size_t client_params_len = 0;
//    char server_Ps[1024] = { 0 };
//
//     wbcrypto_ecdsa_coop_keygen_client_send_key(&client,client_params, sizeof(client_params), client_params_len, mbedtls_ctr_drbg_random, &ctr_drbg );
	 test_ecdsa_coop_scheme(&rr, &ss, hash_msg, 9, mbedtls_ctr_drbg_random, &ctr_drbg);

	 printf("ok");


//
//	 MBEDTLS_MPI_CHK(test_keygen(&client, &server));
//	 MBEDTLS_MPI_CHK(test_encrypt_decrypt(&client, &server));
//	 MBEDTLS_MPI_CHK(test_sign_verify(&client, &server));

cleanup:
	wbcrypto_ecdsa_coop_client_context_free(&client);
	wbcrypto_ecdsa_coop_server_context_free(&server);
	return ret;
}
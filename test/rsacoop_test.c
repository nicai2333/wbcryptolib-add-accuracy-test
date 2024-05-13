#include <ctype.h>
#include <memory.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include "wbcrypto/rsacoop.h"
#include "wbcrypto/internal/sm2/sm2_utils.h"
#include "hex_utils.h"

char rand_value[] = "4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F";

int test_keygen(wbcrypto_rsacoop_client_context* client_key, wbcrypto_rsacoop_server_context* server_key) {
	int ret = 0;
	char req_buf[1024] = { 0 };
	size_t req_len = 0;
	char resp_buf[1024] = { 0 };
	size_t resp_len = 0;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	wbcrypto_rsacoop_keygen_client_session client;
	wbcrypto_rsacoop_keygen_server_session server;
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	wbcrypto_rsacoop_keygen_client_session_init(&client);
	wbcrypto_rsacoop_keygen_server_session_init(&server);

	MBEDTLS_MPI_CHK(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, "test", 4));

	MBEDTLS_MPI_CHK(wbcrypto_rsacoop_keygen_client_start(
		&client,
		2048, 65537,
		req_buf, sizeof(req_buf), &req_len,
		mbedtls_ctr_drbg_random, &ctr_drbg
	));

	MBEDTLS_MPI_CHK(wbcrypto_rsacoop_keygen_server_respond(
		&server,
		2048, 65537,
		req_buf, req_len,
		resp_buf, sizeof(resp_buf), &resp_len,
		mbedtls_ctr_drbg_random, &ctr_drbg
	));

	MBEDTLS_MPI_CHK(wbcrypto_rsacoop_keygen_client_complete(
		&client,
		resp_buf, resp_len
	));

	MBEDTLS_MPI_CHK(wbcrypto_rsacoop_keygen_client_extract_key(
		client_key, &client
	));
	MBEDTLS_MPI_CHK(wbcrypto_rsacoop_keygen_server_extract_key(
		server_key, &server
	));

cleanup:
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	wbcrypto_rsacoop_keygen_client_session_free(&client);
	wbcrypto_rsacoop_keygen_server_session_free(&server);
	return ret;
}

int test_sign_verify(
	const wbcrypto_rsacoop_client_context* client, 
	const wbcrypto_rsacoop_server_context* server
) {
	int ret = 0;
	char msg_buf[] = "signature standard";
	char sig_buf[1024] = { 0 };
	size_t sig_len = 0;
	char dgst_buf[1024] = { 0 };
	size_t dgst_len = 0;
	char req_buf[1024] = { 0 };
	size_t req_len = 0;
	char resp_buf[1024] = { 0 };
	size_t resp_len = 0;
	const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

	MBEDTLS_MPI_CHK(wbcrypto_rsacoop_sign_client_start(
		client,
		info,
		msg_buf, sizeof(msg_buf) - 1,
		dgst_buf, sizeof(dgst_buf), &dgst_len,
		req_buf, sizeof(req_buf), &req_len
	));

	MBEDTLS_MPI_CHK(wbcrypto_rsacoop_sign_server_respond(
		server,
		dgst_buf, dgst_len,
		req_buf, req_len,
		resp_buf, sizeof(resp_buf), &resp_len
	));

	MBEDTLS_MPI_CHK(wbcrypto_rsacoop_sign_client_complete(
		client,
		resp_buf, resp_len,
		sig_buf, sizeof(sig_buf), &sig_len
	));

	MBEDTLS_MPI_CHK(wbcrypto_rsacoop_verify(
		client,
		info,
		msg_buf, sizeof(msg_buf) - 1,
		sig_buf, sig_len
	));

cleanup:
	return ret;
}

int main() {
	int ret = 0;

	wbcrypto_rsacoop_client_context client;
	wbcrypto_rsacoop_server_context server;
	wbcrypto_rsacoop_client_context_init(&client);
	wbcrypto_rsacoop_server_context_init(&server);

	MBEDTLS_MPI_CHK(test_keygen(&client, &server));
	MBEDTLS_MPI_CHK(test_sign_verify(&client, &server));

cleanup:
	wbcrypto_rsacoop_client_context_free(&client);
	wbcrypto_rsacoop_server_context_free(&server);
	return ret;
}
#include "keygen.h"
#include "../hex_utils.h"


int keygen(wbcrypto_sm2coop_context* client_key, wbcrypto_sm2coop_context* server_key, char rand_value[65]) {
	int ret = 0;
	char client_w_buf[1024] = { 0 };
	size_t client_w_len = 0;
	char server_w_buf[1024] = { 0 };
	size_t server_w_len = 0;
	wbcrypto_sm2coop_keygen_session client, server;
	wbcrypto_sm2coop_keygen_session_init(&client);
	client.key.grp = client_key->grp;
	wbcrypto_sm2coop_keygen_session_init(&server);
	server.key.grp = server_key->grp;
	
	MBEDTLS_MPI_CHK(wbcrypto_sm2coop_keygen_client_send_key(
		&client,
		client_w_buf, sizeof(client_w_buf), &client_w_len,
		&mock_rand_hex, rand_value
	));

	MBEDTLS_MPI_CHK(wbcrypto_sm2coop_keygen_server_exchange_key(
		&server,
		client_w_buf, client_w_len,
		server_w_buf, sizeof(server_w_buf), &server_w_len,
		&mock_rand_hex, rand_value
	));

	MBEDTLS_MPI_CHK(wbcrypto_sm2coop_keygen_client_receive_key(
		&client,
		server_w_buf, server_w_len
	));

	MBEDTLS_MPI_CHK(wbcrypto_sm2coop_context_copy(client_key, &client.key));
	MBEDTLS_MPI_CHK(wbcrypto_sm2coop_context_copy(server_key, &server.key));

cleanup:
	mbedtls_ecp_group_init(&client.key.grp);
	mbedtls_ecp_group_init(&server.key.grp);
	wbcrypto_sm2coop_keygen_session_free(&client);
	wbcrypto_sm2coop_keygen_session_free(&server);
	return ret;
}
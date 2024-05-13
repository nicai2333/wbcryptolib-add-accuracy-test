#include "keygen.h"
#include "wbcrypto/sm2coop.h"
#include "../hex_utils.h"
#include "asserts.h"

char rand_value[] = "4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F";


int test_init_keygen_context_works() {
	int ret = 0;
	wbcrypto_sm2coop_keygen_session ctx;

	
	wbcrypto_sm2coop_keygen_session_init(&ctx);

	USE_CLEANUP
cleanup:
	wbcrypto_sm2coop_keygen_session_free(&ctx);
	return ret;
}


int test_copy_keygen_context_works() {
	int ret = 0;
	wbcrypto_sm2coop_keygen_session from, to;
	
	wbcrypto_sm2coop_keygen_session_init(&from);
	wbcrypto_sm2coop_keygen_session_init(&to);

	
	ASSERT_SUCCESS(wbcrypto_sm2coop_keygen_session_copy(&from, &to));

	
cleanup:
	wbcrypto_sm2coop_keygen_session_free(&from);
	wbcrypto_sm2coop_keygen_session_free(&to);
	return ret;
}

int test_copy_keygen_context_handles_null() {
	int ret = 0;
	wbcrypto_sm2coop_keygen_session from, to;
	
	wbcrypto_sm2coop_keygen_session_init(&from);
	wbcrypto_sm2coop_keygen_session_init(&to);

	
	ASSERT_ERROR_CODE(wbcrypto_sm2coop_keygen_session_copy(&from, NULL), WBCRYPTO_ERR_SM2COOP_BAD_INPUT_DATA);
	ASSERT_ERROR_CODE(wbcrypto_sm2coop_keygen_session_copy(NULL, &to), WBCRYPTO_ERR_SM2COOP_BAD_INPUT_DATA);
	ASSERT_ERROR_CODE(wbcrypto_sm2coop_keygen_session_copy(NULL, NULL), WBCRYPTO_ERR_SM2COOP_BAD_INPUT_DATA);

	
cleanup:
	wbcrypto_sm2coop_keygen_session_free(&to);
	return ret;
}


int test_free_keygen_context_works() {
	int ret = 0;
	wbcrypto_sm2coop_keygen_session ctx;
	
	wbcrypto_sm2coop_keygen_session_init(&ctx);

	
	(wbcrypto_sm2coop_keygen_session_free(&ctx));

	USE_CLEANUP
cleanup:
	return ret;
}

int test_free_keygen_context_handles_null() {

	
	wbcrypto_sm2coop_keygen_session_free(NULL);


	return 0;
}


int test_keygen_client_send_key_works() {
	int ret = 0;
	wbcrypto_sm2coop_keygen_session ctx;
	uint8_t client_w_buf[1024] = { 0 };
	size_t used = 0;

	wbcrypto_sm2coop_keygen_session_init(&ctx);
	wbcrypto_sm2coop_load_default_group(&ctx.key.grp);

	ASSERT_SUCCESS(wbcrypto_sm2coop_keygen_client_send_key(
		&ctx, 
		client_w_buf, sizeof(client_w_buf), &used,
		mock_rand_hex, rand_value
	));

	
cleanup:
	wbcrypto_sm2coop_keygen_session_free(&ctx);
	return ret;
}

int test_keygen_client_send_key_handles_boundary_values() {
	int ret = 0;
	wbcrypto_sm2coop_keygen_session ctx;
	uint8_t client_w_buf[1024] = { 0 };
	size_t used = 0;

	wbcrypto_sm2coop_keygen_session_init(&ctx);
	wbcrypto_sm2coop_load_default_group(&ctx.key.grp);
	
	//case: client_w_buf too small
	ASSERT_ERROR_CODE(
		wbcrypto_sm2coop_keygen_client_send_key(
			&ctx,
			client_w_buf, 1, &used,
			mock_rand_hex, rand_value
		),
		WBCRYPTO_ERR_SM2COOP_OUTPUT_TOO_LARGE
	);

	
cleanup:
	wbcrypto_sm2coop_keygen_session_free(&ctx);
	return ret;
}


int test_keygen_server_exchange_key_works() {
	int ret = 0;
	wbcrypto_sm2coop_keygen_session ctx;
	uint8_t client_w_buf[1024] = { 0 };
	size_t client_w_size;
	uint8_t server_w_buf[1024] = { 0 };
	size_t server_w_size;
	
	hex_to_binary(
		"3045022011C88AE04CEC1BA554D03D5B5970333A83585826C2A985DE5520D9E934389EFB02210084B52D344FB21AA8EA38A4940C8332692B8D4DA2393549212EAFDC0F11CA5C9C", 
		client_w_buf, sizeof(client_w_buf)
	);
	client_w_size = 71;

	wbcrypto_sm2coop_keygen_session_init(&ctx);
	wbcrypto_sm2coop_load_default_group(&ctx.key.grp);
	
	ASSERT_SUCCESS(wbcrypto_sm2coop_keygen_server_exchange_key(
		&ctx,
		client_w_buf, client_w_size,
		server_w_buf, sizeof(server_w_buf), &server_w_size,
		mock_rand_hex, rand_value
	));


cleanup:
	wbcrypto_sm2coop_keygen_session_free(&ctx);
	return ret;
}

int test_keygen_server_exchange_key_handles_boundary_values() {
	int ret = 0;
	wbcrypto_sm2coop_keygen_session ctx;
	uint8_t client_w_buf[1024] = { 0 };
	size_t client_w_size;
	uint8_t server_w_buf[1024] = { 0 };
	size_t server_w_size;

	hex_to_binary(
		"3045022011C88AE04CEC1BA554D03D5B5970333A83585826C2A985DE5520D9E934389EFB02210084B52D344FB21AA8EA38A4940C8332692B8D4DA2393549212EAFDC0F11CA5C9C",
		client_w_buf, sizeof(client_w_buf)
	);
	client_w_size = 71;
	
	wbcrypto_sm2coop_keygen_session_init(&ctx);
	wbcrypto_sm2coop_load_default_group(&ctx.key.grp);
	
	//case: client_w invalid (truncated)
	ASSERT_ERROR_CODE(
		wbcrypto_sm2coop_keygen_server_exchange_key(
			&ctx,
			client_w_buf, 17,
			server_w_buf, sizeof(server_w_buf), &server_w_size,
			mock_rand_hex, rand_value
		),
		WBCRYPTO_ERR_SM2COOP_BAD_INPUT_DATA
	);

	wbcrypto_sm2coop_keygen_session_free(&ctx);
	wbcrypto_sm2coop_keygen_session_init(&ctx);
	wbcrypto_sm2coop_load_default_group(&ctx.key.grp);

	//case: server_w output too small
	ASSERT_ERROR_CODE(
		wbcrypto_sm2coop_keygen_server_exchange_key(
			&ctx,
			client_w_buf, client_w_size,
			server_w_buf, 1, &server_w_size,
			mock_rand_hex, rand_value
		),
		WBCRYPTO_ERR_SM2COOP_OUTPUT_TOO_LARGE
	);

	
cleanup:
	wbcrypto_sm2coop_keygen_session_free(&ctx);
	return ret;
}


int test_keygen_client_receive_key_works() {
	int ret = 0;
	wbcrypto_sm2coop_keygen_session ctx;
	uint8_t client_w_buf[1024] = { 0 };
	size_t client_w_size;
	uint8_t server_w_buf[1024] = { 0 };
	size_t server_w_size;

	hex_to_binary(
		"3045022011C88AE04CEC1BA554D03D5B5970333A83585826C2A985DE5520D9E934389EFB02210084B52D344FB21AA8EA38A4940C8332692B8D4DA2393549212EAFDC0F11CA5C9C",
		server_w_buf, sizeof(server_w_buf)
	);
	server_w_size = 71;

	wbcrypto_sm2coop_keygen_session_init(&ctx);
	wbcrypto_sm2coop_load_default_group(&ctx.key.grp);
	
	ASSERT_SUCCESS(wbcrypto_sm2coop_keygen_client_send_key(
		&ctx,
		client_w_buf, sizeof(client_w_buf), &client_w_size,
		mock_rand_hex, rand_value
	));
	
	
	ASSERT_SUCCESS(wbcrypto_sm2coop_keygen_client_receive_key(
		&ctx,
		server_w_buf, server_w_size
	));

	
cleanup:
	wbcrypto_sm2coop_keygen_session_free(&ctx);
	return ret;
}

int test_keygen_client_receive_key_handles_boundary_values() {
	int ret = 0;
	wbcrypto_sm2coop_keygen_session ctx;
	uint8_t client_w_buf[1024] = { 0 };
	size_t client_w_size;
	uint8_t server_w_buf[1024] = { 0 };

	hex_to_binary(
		"3045022011C88AE04CEC1BA554D03D5B5970333A83585826C2A985DE5520D9E934389EFB02210084B52D344FB21AA8EA38A4940C8332692B8D4DA2393549212EAFDC0F11CA5C9C",
		server_w_buf, sizeof(server_w_buf)
	);

	wbcrypto_sm2coop_keygen_session_init(&ctx);
	wbcrypto_sm2coop_load_default_group(&ctx.key.grp);

	ASSERT_SUCCESS(wbcrypto_sm2coop_keygen_client_send_key(
		&ctx,
		client_w_buf, sizeof(client_w_buf), &client_w_size,
		mock_rand_hex, rand_value
	));


	//case server_w_buf invalid(truncated)
	ASSERT_ERROR_CODE(
		wbcrypto_sm2coop_keygen_client_receive_key(
			&ctx,
			server_w_buf, 17
		),
		WBCRYPTO_ERR_SM2COOP_BAD_INPUT_DATA
	);

	
cleanup:
	wbcrypto_sm2coop_keygen_session_free(&ctx);
	return ret;
}



int test_keygen_whole_process_works() {
	int ret = 0;
	wbcrypto_sm2coop_context client, server;
	wbcrypto_sm2coop_context_init(&client);
	wbcrypto_sm2coop_load_default_group(&client.grp);
	wbcrypto_sm2coop_context_init(&server);
	wbcrypto_sm2coop_load_default_group(&server.grp);

	
	ASSERT_SUCCESS(keygen(&client, &server, rand_value));

	
cleanup:
	wbcrypto_sm2coop_context_free(&client);
	wbcrypto_sm2coop_context_free(&server);
	return ret;
}

int main() {
	int ret = 0;

	//context functions
	ASSERT_SUCCESS(test_init_keygen_context_works());
	ASSERT_SUCCESS(test_copy_keygen_context_works());
	ASSERT_SUCCESS(test_copy_keygen_context_handles_null());
	ASSERT_SUCCESS(test_free_keygen_context_works());
	ASSERT_SUCCESS(test_free_keygen_context_handles_null());

	//keygen process
	ASSERT_SUCCESS(test_keygen_client_send_key_works());
	ASSERT_SUCCESS(test_keygen_client_send_key_handles_boundary_values());

	ASSERT_SUCCESS(test_keygen_server_exchange_key_works());
	ASSERT_SUCCESS(test_keygen_server_exchange_key_handles_boundary_values());

	ASSERT_SUCCESS(test_keygen_client_receive_key_works());
	ASSERT_SUCCESS(test_keygen_client_receive_key_handles_boundary_values());

	//integration
	ASSERT_SUCCESS(test_keygen_whole_process_works());
	
cleanup:
	return ret;
}

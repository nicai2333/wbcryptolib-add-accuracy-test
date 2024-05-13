#include "keygen.h"
#include "wbcrypto/sm2coop.h"
#include "../hex_utils.h"
#include "asserts.h"
#include <string.h>

char rand_value[] = "4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F";


int test_init_decrypt_client_context_works() {
	int ret = 0;
	wbcrypto_sm2coop_decrypt_client_session ctx;

	
	wbcrypto_sm2coop_decrypt_client_session_init(&ctx);

	USE_CLEANUP
cleanup:
	wbcrypto_sm2coop_decrypt_client_session_free(&ctx);
	return ret;
}


int test_copy_decrypt_client_context_works() {
	int ret = 0;
	wbcrypto_sm2coop_decrypt_client_session from, to;
	
	wbcrypto_sm2coop_decrypt_client_session_init(&from);
	wbcrypto_sm2coop_decrypt_client_session_init(&to);

	
	ASSERT_SUCCESS(wbcrypto_sm2coop_decrypt_client_session_copy(&from, &to));

	
cleanup:
	wbcrypto_sm2coop_decrypt_client_session_free(&from);
	wbcrypto_sm2coop_decrypt_client_session_free(&to);
	return ret;
}

int test_copy_decrypt_client_context_handles_null() {
	int ret = 0;
	wbcrypto_sm2coop_decrypt_client_session from, to;
	
	wbcrypto_sm2coop_decrypt_client_session_init(&from);
	wbcrypto_sm2coop_decrypt_client_session_init(&to);

	
	ASSERT_ERROR_CODE(wbcrypto_sm2coop_decrypt_client_session_copy(&from, NULL), WBCRYPTO_ERR_SM2COOP_BAD_INPUT_DATA);
	ASSERT_ERROR_CODE(wbcrypto_sm2coop_decrypt_client_session_copy(NULL, &to), WBCRYPTO_ERR_SM2COOP_BAD_INPUT_DATA);
	ASSERT_ERROR_CODE(wbcrypto_sm2coop_decrypt_client_session_copy(NULL, NULL), WBCRYPTO_ERR_SM2COOP_BAD_INPUT_DATA);

	
cleanup:
	wbcrypto_sm2coop_decrypt_client_session_free(&to);
	return ret;
}


int test_free_decrypt_client_context_works() {
	int ret = 0;
	wbcrypto_sm2coop_decrypt_client_session ctx;
	
	wbcrypto_sm2coop_decrypt_client_session_init(&ctx);

	
	(wbcrypto_sm2coop_decrypt_client_session_free(&ctx));

	USE_CLEANUP
cleanup:
	return ret;
}

int test_free_decrypt_client_context_handles_null() {

	
	wbcrypto_sm2coop_decrypt_client_session_free(NULL);


	return 0;
}


int test_encrypt_works(wbcrypto_sm2coop_context* source) {
	int ret = 0;
	char plaintext_buf[] = "encryption standard";
	uint8_t ciphertext_buf[1024] = { 0 };
	uint8_t expected_ciphertext_buf[1024] = { 0 };
	size_t ciphertext_len = 0;
	wbcrypto_sm2coop_context ctx;

	hex_to_binary(
		"307C022011C88AE04CEC1BA554D03D5B5970333A83585826C2A985DE5520D9E934389EFB02210084B52D344FB21AA8EA38A4940C8332692B8D4DA2393549212EAFDC0F11CA5C9C04206FF782BFA5D686714134549F024E74900E682679E46433C36B49665284A200D3041304E8FC865850C0A1D8D133D8F4470F8ED5FBB1",
		expected_ciphertext_buf,
		126
	);

	wbcrypto_sm2coop_context_init(&ctx);
	ASSERT_SUCCESS(wbcrypto_sm2coop_load_default_group(&ctx.grp));
	ASSERT_SUCCESS(mbedtls_mpi_copy(&ctx.P.X, &source->P.X));
	ASSERT_SUCCESS(mbedtls_mpi_copy(&ctx.P.Y, &source->P.Y));
	ASSERT_SUCCESS(mbedtls_mpi_copy(&ctx.P.Z, &source->P.Z));

	
	ASSERT_SUCCESS(wbcrypto_sm2coop_encrypt(
		&ctx,
		(uint8_t*)plaintext_buf, sizeof(plaintext_buf) - 1,
		ciphertext_buf, sizeof(ciphertext_buf), &ciphertext_len,
		mock_rand_hex, rand_value
	));

	
	ASSERT_SUCCESS(memcmp(expected_ciphertext_buf, ciphertext_buf, 126));

cleanup:
	wbcrypto_sm2coop_context_free(&ctx);
	return ret;
}

int test_encrypt_handles_boundary_values(wbcrypto_sm2coop_context* source) {
	int ret = 0;
	char plaintext_buf[] = "encryption standard";
	uint8_t ciphertext_buf[1024] = { 0 };
	size_t ciphertext_len = 0;
	wbcrypto_sm2coop_context ctx;

	wbcrypto_sm2coop_context_init(&ctx);
	ASSERT_SUCCESS(wbcrypto_sm2coop_load_default_group(&ctx.grp));
	ASSERT_SUCCESS(mbedtls_mpi_copy(&ctx.P.X, &source->P.X));
	ASSERT_SUCCESS(mbedtls_mpi_copy(&ctx.P.Y, &source->P.Y));
	ASSERT_SUCCESS(mbedtls_mpi_copy(&ctx.P.Z, &source->P.Z));


	//case: buffer too small
	ASSERT_ERROR_CODE(
		wbcrypto_sm2coop_encrypt(
			&ctx,
			(uint8_t*)plaintext_buf, sizeof(plaintext_buf) - 1,
			ciphertext_buf, 1, &ciphertext_len,
			mock_rand_hex, rand_value
		),
		WBCRYPTO_ERR_SM2COOP_OUTPUT_TOO_LARGE
	);

	
cleanup:
	wbcrypto_sm2coop_context_free(&ctx);
	return ret;
}


int test_decrypt_client_start_works(wbcrypto_sm2coop_context* client, wbcrypto_sm2coop_context* server) {
	int ret = 0;
	uint8_t ciphertext_buf[1024] = { 0 };
	size_t ciphertext_len;
	uint8_t client_request_buf[1024] = { 0 };
	size_t client_request_len = 0;
	uint8_t expected_client_request_buf[1024] = { 0 };
	size_t expected_client_request_len;

	hex_to_binary(
		"307C022011C88AE04CEC1BA554D03D5B5970333A83585826C2A985DE5520D9E934389EFB02210084B52D344FB21AA8EA38A4940C8332692B8D4DA2393549212EAFDC0F11CA5C9C04206FF782BFA5D686714134549F024E74900E682679E46433C36B49665284A200D3041304E8FC865850C0A1D8D133D8F4470F8ED5FBB1",
		ciphertext_buf,
		126
	);
	ciphertext_len = 126;

	hex_to_binary(
		"3045022011C88AE04CEC1BA554D03D5B5970333A83585826C2A985DE5520D9E934389EFB02210084B52D344FB21AA8EA38A4940C8332692B8D4DA2393549212EAFDC0F11CA5C9C",
		expected_client_request_buf,
		71
	);
	expected_client_request_len = 71;

	wbcrypto_sm2coop_decrypt_client_session decrypt_ctx;
	wbcrypto_sm2coop_decrypt_client_session_init(&decrypt_ctx);


	MBEDTLS_MPI_CHK(wbcrypto_sm2coop_decrypt_client_start(
		client,
		&decrypt_ctx,
		ciphertext_buf, ciphertext_len,
		client_request_buf, sizeof(client_request_buf), &client_request_len
	));
	
	ASSERT_SUCCESS(memcmp(expected_client_request_buf, client_request_buf, client_request_len));

	USE_VAR(expected_client_request_len);
cleanup:
	wbcrypto_sm2coop_decrypt_client_session_free(&decrypt_ctx);
	return ret;
}

int test_decrypt_client_start_handles_boundary_values(wbcrypto_sm2coop_context* client, wbcrypto_sm2coop_context* server) {
	int ret = 0;
	uint8_t ciphertext_buf[1024] = { 0 };
	size_t ciphertext_len = 0;
	uint8_t client_request_buf[1024] = { 0 };
	size_t client_request_len = 0;
	uint8_t expected_client_request_buf[1024] = { 0 };
	size_t expected_client_request_len = 0;

	hex_to_binary(
		"307C022011C88AE04CEC1BA554D03D5B5970333A83585826C2A985DE5520D9E934389EFB02210084B52D344FB21AA8EA38A4940C8332692B8D4DA2393549212EAFDC0F11CA5C9C04206FF782BFA5D686714134549F024E74900E682679E46433C36B49665284A200D3041304E8FC865850C0A1D8D133D8F4470F8ED5FBB1",
		ciphertext_buf,
		126
	);
	ciphertext_len = 126;

	hex_to_binary(
		"3045022011C88AE04CEC1BA554D03D5B5970333A83585826C2A985DE5520D9E934389EFB02210084B52D344FB21AA8EA38A4940C8332692B8D4DA2393549212EAFDC0F11CA5C9C",
		expected_client_request_buf,
		71
	);
	expected_client_request_len = 71;

	wbcrypto_sm2coop_decrypt_client_session decrypt_ctx;
	wbcrypto_sm2coop_decrypt_client_session_init(&decrypt_ctx);


	//case: client_request too small
	ASSERT_ERROR_CODE(
		wbcrypto_sm2coop_decrypt_client_start(
			client,
			&decrypt_ctx,
			ciphertext_buf, ciphertext_len,
			client_request_buf, 1, &client_request_len
		),
		WBCRYPTO_ERR_SM2COOP_OUTPUT_TOO_LARGE	
	);

	USE_VAR(client_request_len);
	USE_VAR(expected_client_request_len);
cleanup:
	wbcrypto_sm2coop_decrypt_client_session_free(&decrypt_ctx);
	return ret;
}


int test_decrypt_server_respond_works(wbcrypto_sm2coop_context* client, wbcrypto_sm2coop_context* server) {
	int ret = 0;
	uint8_t client_request_buf[1024] = { 0 };
	size_t client_request_len = 0;
	uint8_t server_response_buf[1024] = { 0 };
	size_t server_response_len = 0;
	uint8_t expected_server_response_buf[1024] = { 0 };
	size_t expected_server_response_len = 0;

	hex_to_binary(
		"3045022011C88AE04CEC1BA554D03D5B5970333A83585826C2A985DE5520D9E934389EFB02210084B52D344FB21AA8EA38A4940C8332692B8D4DA2393549212EAFDC0F11CA5C9C",
		client_request_buf,
		71
	);
	client_request_len = 71;

	hex_to_binary(
		"30450220092075504F9EB856DCE7D29318D97C6FFF0A41ED067678C603A7A8CB9E184690022100C3BEEEE2E6DD43AC80851166095A66E46B5AD8448DE2AC333A2B3F22A8A63611",
		expected_server_response_buf,
		71
	);
	expected_server_response_len = 71;

	
	MBEDTLS_MPI_CHK(wbcrypto_sm2coop_decrypt_server_respond(
		server,
		client_request_buf, client_request_len,
		server_response_buf, sizeof(server_response_buf), &server_response_len,
		mock_rand_hex, rand_value
	));

	ASSERT_SUCCESS(memcmp(expected_server_response_buf, server_response_buf, server_response_len));

	USE_VAR(client_request_len);
	USE_VAR(expected_server_response_len);
cleanup:
	return ret;
}

int test_decrypt_server_respond_handles_boundary_values(wbcrypto_sm2coop_context* client, wbcrypto_sm2coop_context* server) {
	int ret = 0;
	uint8_t client_request_buf[1024] = { 0 };
	size_t client_request_len = 0;
	uint8_t server_response_buf[1024] = { 0 };
	size_t server_response_len = 0;
	uint8_t expected_server_response_buf[1024] = { 0 };
	size_t expected_server_response_len = 0;

	hex_to_binary(
		"3045022011C88AE04CEC1BA554D03D5B5970333A83585826C2A985DE5520D9E934389EFB02210084B52D344FB21AA8EA38A4940C8332692B8D4DA2393549212EAFDC0F11CA5C9C",
		client_request_buf,
		71
	);
	client_request_len = 71;

	hex_to_binary(
		"30450220092075504F9EB856DCE7D29318D97C6FFF0A41ED067678C603A7A8CB9E184690022100C3BEEEE2E6DD43AC80851166095A66E46B5AD8448DE2AC333A2B3F22A8A63611",
		expected_server_response_buf,
		71
	);
	expected_server_response_len = 71;


	//case: request invalid(truncated)
	ASSERT_ERROR_CODE(
		wbcrypto_sm2coop_decrypt_server_respond(
			server,
			client_request_buf+3, 3,
			server_response_buf, sizeof(server_response_buf), &server_response_len,
			mock_rand_hex, rand_value
		),
		WBCRYPTO_ERR_SM2COOP_BAD_INPUT_DATA	
	);

	//case: response too small
	ASSERT_ERROR_CODE(
		wbcrypto_sm2coop_decrypt_server_respond(
			server,
			client_request_buf, client_request_len,
			server_response_buf, 1, &server_response_len,
			mock_rand_hex, rand_value
		),
		WBCRYPTO_ERR_SM2COOP_OUTPUT_TOO_LARGE
	);

	USE_VAR(client_request_len);
	USE_VAR(expected_server_response_len);
cleanup:
	return ret;
}


int test_decrypt_client_complete_works(wbcrypto_sm2coop_context* client, wbcrypto_sm2coop_context* server) {
	int ret = 0;
	uint8_t ciphertext_buf[1024] = { 0 };
	size_t ciphertext_len = 0;
	uint8_t client_request_buf[1024] = { 0 };
	size_t client_request_len = 0;
	uint8_t server_response_buf[1024] = { 0 };
	size_t server_response_len = 0;
	uint8_t plaintext_buf[1024] = { 0 };
	size_t plaintext_len = 0;
	char expected_plaintext[] = "encryption standard";

	hex_to_binary(
		"307C022011C88AE04CEC1BA554D03D5B5970333A83585826C2A985DE5520D9E934389EFB02210084B52D344FB21AA8EA38A4940C8332692B8D4DA2393549212EAFDC0F11CA5C9C04206FF782BFA5D686714134549F024E74900E682679E46433C36B49665284A200D3041304E8FC865850C0A1D8D133D8F4470F8ED5FBB1",
		ciphertext_buf,
		126
	);
	ciphertext_len = 126;

	hex_to_binary(
		"30450220092075504F9EB856DCE7D29318D97C6FFF0A41ED067678C603A7A8CB9E184690022100C3BEEEE2E6DD43AC80851166095A66E46B5AD8448DE2AC333A2B3F22A8A63611",
		server_response_buf,
		71
	);
	server_response_len = 71;

	wbcrypto_sm2coop_decrypt_client_session decrypt_ctx;
	wbcrypto_sm2coop_decrypt_client_session_init(&decrypt_ctx);

	MBEDTLS_MPI_CHK(wbcrypto_sm2coop_decrypt_client_start(
		client,
		&decrypt_ctx,
		ciphertext_buf, ciphertext_len,
		client_request_buf, sizeof(client_request_buf), &client_request_len
	));

	
	MBEDTLS_MPI_CHK(wbcrypto_sm2coop_decrypt_client_complete(
		client, &decrypt_ctx,
		server_response_buf, server_response_len,
		ciphertext_buf, ciphertext_len,
		plaintext_buf, sizeof(plaintext_buf), &plaintext_len
	));

	MBEDTLS_MPI_CHK(memcmp(expected_plaintext, plaintext_buf, plaintext_len));

	
cleanup:
	wbcrypto_sm2coop_decrypt_client_session_free(&decrypt_ctx);
	return ret;
}

int test_decrypt_client_complete_handles_boundary_values(wbcrypto_sm2coop_context* client, wbcrypto_sm2coop_context* server) {
	int ret = 0;
	uint8_t ciphertext_buf[1024] = { 0 };
	size_t ciphertext_len = 0;
	uint8_t client_request_buf[1024] = { 0 };
	size_t client_request_len = 0;
	uint8_t server_response_buf[1024] = { 0 };
	size_t server_response_len = 0;
	uint8_t plaintext_buf[1024] = { 0 };
	size_t plaintext_len = 0;

	hex_to_binary(
		"307C022011C88AE04CEC1BA554D03D5B5970333A83585826C2A985DE5520D9E934389EFB02210084B52D344FB21AA8EA38A4940C8332692B8D4DA2393549212EAFDC0F11CA5C9C04206FF782BFA5D686714134549F024E74900E682679E46433C36B49665284A200D3041304E8FC865850C0A1D8D133D8F4470F8ED5FBB1",
		ciphertext_buf,
		126
	);
	ciphertext_len = 126;

	hex_to_binary(
		"30450220092075504F9EB856DCE7D29318D97C6FFF0A41ED067678C603A7A8CB9E184690022100C3BEEEE2E6DD43AC80851166095A66E46B5AD8448DE2AC333A2B3F22A8A63611",
		server_response_buf,
		71
	);
	server_response_len = 71;

	wbcrypto_sm2coop_decrypt_client_session decrypt_ctx;
	wbcrypto_sm2coop_decrypt_client_session_init(&decrypt_ctx);


	MBEDTLS_MPI_CHK(wbcrypto_sm2coop_decrypt_client_start(
		client,
		&decrypt_ctx,
		ciphertext_buf, ciphertext_len,
		client_request_buf, sizeof(client_request_buf), &client_request_len
	));

	
	//case: response invalid(truncated)
	ASSERT_ERROR_CODE(
		wbcrypto_sm2coop_decrypt_client_complete(
			client, &decrypt_ctx,
			server_response_buf+3, 17,
			ciphertext_buf, ciphertext_len,
			plaintext_buf, sizeof(plaintext_buf), &plaintext_len
		),
		WBCRYPTO_ERR_SM2COOP_BAD_INPUT_DATA
	);

	//case: ciphertext invalid(truncated)
	ASSERT_ERROR_CODE(
		wbcrypto_sm2coop_decrypt_client_complete(
			client, &decrypt_ctx,
			server_response_buf, server_response_len,
			ciphertext_buf+3, 3,
			plaintext_buf, sizeof(plaintext_buf), &plaintext_len
		),
		WBCRYPTO_ERR_SM2COOP_BAD_INPUT_DATA
	);

	//case: plaintext too small
	ASSERT_ERROR_CODE(
		wbcrypto_sm2coop_decrypt_client_complete(
			client, &decrypt_ctx,
			server_response_buf, server_response_len,
			ciphertext_buf, ciphertext_len,
			plaintext_buf, 1, &plaintext_len
		),
		WBCRYPTO_ERR_SM2COOP_OUTPUT_TOO_LARGE
	);

	
cleanup:
	wbcrypto_sm2coop_decrypt_client_session_free(&decrypt_ctx);
	return ret;
}


int test_entire_process_works(wbcrypto_sm2coop_context* client, wbcrypto_sm2coop_context* server) {
	int ret = 0;
	char plaintext_buf[] = "encryption standard";
	unsigned char ciphertext_buf[1024] = { 0 };
	size_t ciphertext_len = 0;
	unsigned char client_request_buf[1024] = { 0 };
	size_t client_request_len = 0;
	unsigned char server_response_buf[1024] = { 0 };
	size_t server_response_len = 0;
	unsigned char decrypted_buf[1024] = { 0 };
	size_t decrypted_len = 0;

	wbcrypto_sm2coop_decrypt_client_session decrypt_ctx;
	wbcrypto_sm2coop_decrypt_client_session_init(&decrypt_ctx);

	MBEDTLS_MPI_CHK(wbcrypto_sm2coop_encrypt(
		client,
		(unsigned char*)plaintext_buf, sizeof(plaintext_buf) - 1,
		ciphertext_buf, sizeof(ciphertext_buf), &ciphertext_len,
		mock_rand_hex, rand_value
	));

	MBEDTLS_MPI_CHK(wbcrypto_sm2coop_decrypt_client_start(
		client,
		&decrypt_ctx,
		ciphertext_buf, ciphertext_len,
		client_request_buf, sizeof(client_request_buf), &client_request_len
	));

	MBEDTLS_MPI_CHK(wbcrypto_sm2coop_decrypt_server_respond(
		server,
		client_request_buf, client_request_len,
		server_response_buf, sizeof(server_response_buf), &server_response_len,
		mock_rand_hex, rand_value
	));

	MBEDTLS_MPI_CHK(wbcrypto_sm2coop_decrypt_client_complete(
		client, &decrypt_ctx,
		server_response_buf, server_response_len,
		ciphertext_buf, ciphertext_len,
		decrypted_buf, sizeof(decrypted_buf), &decrypted_len
	));

	MBEDTLS_MPI_CHK(strncmp((char*)decrypted_buf, plaintext_buf, sizeof(plaintext_buf) - 1));

cleanup:
	wbcrypto_sm2coop_decrypt_client_session_free(&decrypt_ctx);
	return ret;
}


int main() {
	int ret = 0;
	wbcrypto_sm2coop_context client, server;
	wbcrypto_sm2coop_context_init(&client);
	wbcrypto_sm2coop_load_default_group(&client.grp);
	wbcrypto_sm2coop_context_init(&server);
	wbcrypto_sm2coop_load_default_group(&server.grp);

	ASSERT_SUCCESS(keygen(&client, &server, rand_value));

	ASSERT_SUCCESS(test_init_decrypt_client_context_works());
	ASSERT_SUCCESS(test_copy_decrypt_client_context_works());
	ASSERT_SUCCESS(test_copy_decrypt_client_context_handles_null());
	ASSERT_SUCCESS(test_free_decrypt_client_context_works());
	ASSERT_SUCCESS(test_free_decrypt_client_context_handles_null());

	ASSERT_SUCCESS(test_encrypt_works(&client));
	ASSERT_SUCCESS(test_encrypt_handles_boundary_values(&client));
	ASSERT_SUCCESS(test_decrypt_client_start_works(&client, &server));
	ASSERT_SUCCESS(test_decrypt_client_start_handles_boundary_values(&client, &server));
	ASSERT_SUCCESS(test_decrypt_server_respond_works(&client, &server));
	ASSERT_SUCCESS(test_decrypt_server_respond_handles_boundary_values(&client, &server));
	ASSERT_SUCCESS(test_decrypt_client_complete_works(&client, &server));
	ASSERT_SUCCESS(test_decrypt_client_complete_handles_boundary_values(&client, &server));
	
	ASSERT_SUCCESS(test_entire_process_works(&client, &server));

cleanup:
	wbcrypto_sm2coop_context_free(&client);
	wbcrypto_sm2coop_context_free(&server);
	return ret;
}
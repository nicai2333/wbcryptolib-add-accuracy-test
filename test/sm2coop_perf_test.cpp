#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "wbcrypto/sm2coop.h"
#include "hex_utils.h"
#include <chrono>
#include <iostream>

char rand_value[] = "4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F";

template<typename LambdaType>
void run_perf_test(const char* name, int warmup_count, int test_count, LambdaType func) {
	for (int i = 0; i < warmup_count; i++) {
		func();
	}

	auto begin = std::chrono::system_clock::now();
	for (int i = 0; i < test_count; i++) {
		func();
	}
	auto end = std::chrono::system_clock::now();
	auto count = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();

	printf(
		"run [%s] after [%d] times: %d ms\n",
		name, test_count, count
	);
}

int test_keygen(wbcrypto_sm2coop_context* client_key, wbcrypto_sm2coop_context* server_key) {
	int ret = 0;
	unsigned char client_w_buf[1024] = { 0 };
	size_t client_w_len = 0;
	unsigned char server_w_buf[1024] = { 0 };
	size_t server_w_len = 0;
	wbcrypto_sm2coop_keygen_session client, server;
	wbcrypto_sm2coop_keygen_session_init(&client);
	wbcrypto_sm2coop_keygen_session_init(&server);

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
	wbcrypto_sm2coop_keygen_session_free(&client);
	wbcrypto_sm2coop_keygen_session_free(&server);
	return ret;
}



void test_sm2coop_decrypt_client_start_perf(
	wbcrypto_sm2coop_context* client,
	wbcrypto_sm2coop_context* server
) {
	uint64_t ret = 0;
	unsigned char plaintext_buf[] = "encryption standard";
	unsigned char ciphertext_buf[1024] = { 0 };
	size_t ciphertext_len = 0;
	unsigned char client_request_buf[1024] = { 0 };
	size_t client_request_len = 0;

	wbcrypto_sm2coop_decrypt_client_session decrypt_ctx;
	wbcrypto_sm2coop_decrypt_client_session_init(&decrypt_ctx);

	wbcrypto_sm2coop_encrypt(
		client,
		plaintext_buf, sizeof(plaintext_buf) - 1,
		ciphertext_buf, sizeof(ciphertext_buf), &ciphertext_len,
		mock_rand_hex, rand_value
	);

	run_perf_test(
		"SM2Coop decrypt protocol / client_start",
		1000, 1000,
		[&]() {
		wbcrypto_sm2coop_decrypt_client_start(
			client,
			&decrypt_ctx,
			ciphertext_buf, ciphertext_len,
			client_request_buf, sizeof(client_request_buf), &client_request_len
		);
	}
	);

	wbcrypto_sm2coop_decrypt_client_session_free(&decrypt_ctx);
}

void test_sm2coop_decrypt_server_respond_perf(
	wbcrypto_sm2coop_context* client,
	wbcrypto_sm2coop_context* server
) {
	uint64_t ret = 0;
	unsigned char client_request_buf[1024] = { 0 };
	size_t client_request_len = 0;
	unsigned char server_response_buf[1024] = { 0 };
	size_t server_response_len = 0;

	hex_to_binary(
		"3045022011C88AE04CEC1BA554D03D5B5970333A83585826C2A985DE5520D9E934389EFB02210084B52D344FB21AA8EA38A4940C8332692B8D4DA2393549212EAFDC0F11CA5C9C",
		client_request_buf, sizeof(client_request_buf)
	);
	client_request_len = 71;

	run_perf_test(
		"SM2Coop decrypt protocol / server_respond",
		1000, 1000,
		[&]() {
		wbcrypto_sm2coop_decrypt_server_respond(
			server,
			client_request_buf, client_request_len,
			server_response_buf, sizeof(server_response_buf), &server_response_len,
			mock_rand_hex, rand_value
		);
	}
	);

}

void test_sm2coop_decrypt_client_complete_perf(
	wbcrypto_sm2coop_context* client,
	wbcrypto_sm2coop_context* server
) {
	uint64_t ret = 0;
	unsigned char plaintext_buf[] = "encryption standard";
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

	wbcrypto_sm2coop_encrypt(
		client,
		plaintext_buf, sizeof(plaintext_buf) - 1,
		ciphertext_buf, sizeof(ciphertext_buf), &ciphertext_len,
		mock_rand_hex, rand_value
	);

	wbcrypto_sm2coop_decrypt_client_start(
		client,
		&decrypt_ctx,
		ciphertext_buf, ciphertext_len,
		client_request_buf, sizeof(client_request_buf), &client_request_len
	);

	wbcrypto_sm2coop_decrypt_server_respond(
		server,
		client_request_buf, client_request_len,
		server_response_buf, sizeof(server_response_buf), &server_response_len,
		mock_rand_hex, rand_value
	);

	run_perf_test(
		"SM2Coop decrypt protocol / client_complete",
		1000, 1000,
		[&]() {
		wbcrypto_sm2coop_decrypt_client_complete(
			client, &decrypt_ctx,
			server_response_buf, server_response_len,
			ciphertext_buf, ciphertext_len,
			decrypted_buf, sizeof(decrypted_buf), &decrypted_len
		);
	}
	);

	wbcrypto_sm2coop_decrypt_client_session_free(&decrypt_ctx);

}

void test_sm2coop_decrypt_perf(
	wbcrypto_sm2coop_context* client,
	wbcrypto_sm2coop_context* server
) {
	uint64_t ret = 0;
	unsigned char plaintext_buf[] = "encryption standard";
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

	wbcrypto_sm2coop_encrypt(
		client,
		plaintext_buf, sizeof(plaintext_buf) - 1,
		ciphertext_buf, sizeof(ciphertext_buf), &ciphertext_len,
		mock_rand_hex, rand_value
	);

	run_perf_test(
		"SM2Coop decrypt protocol",
		1000, 1000,
		[&]() {

		wbcrypto_sm2coop_decrypt_client_start(
			client,
			&decrypt_ctx,
			ciphertext_buf, ciphertext_len,
			client_request_buf, sizeof(client_request_buf), &client_request_len
		);

		wbcrypto_sm2coop_decrypt_server_respond(
			server,
			client_request_buf, client_request_len,
			server_response_buf, sizeof(server_response_buf), &server_response_len,
			mock_rand_hex, rand_value
		);

		wbcrypto_sm2coop_decrypt_client_complete(
			client, &decrypt_ctx,
			server_response_buf, server_response_len,
			ciphertext_buf, ciphertext_len,
			decrypted_buf, sizeof(decrypted_buf), &decrypted_len
		);
	}
	);

	wbcrypto_sm2coop_decrypt_client_session_free(&decrypt_ctx);

}



void test_sm2coop_sign_client_start_perf(
	wbcrypto_sm2coop_context* client,
	wbcrypto_sm2coop_context* server
) {
	uint64_t ret = 0;
	unsigned char msg_buf[] = "signature standard";
	unsigned char sig_buf[1024] = { 0 };
	size_t sig_len = 0;
	unsigned char dgst_buf[1024] = { 0 };
	size_t dgst_len = 0;
	unsigned char req_buf[1024] = { 0 };
	size_t req_len = 0;
	unsigned char resp_buf[1024] = { 0 };
	size_t resp_len = 0;

	wbcrypto_sm2coop_sign_client_session sign_ctx;
	wbcrypto_sm2coop_sign_client_session_init(&sign_ctx);

	run_perf_test(
		"SM2Coop sign protocol / client_start",
		1000, 1000,
		[&]() {
		wbcrypto_sm2coop_sign_client_start(
			client,
			&sign_ctx,
			msg_buf, sizeof(msg_buf) - 1,
			dgst_buf, sizeof(dgst_buf), &dgst_len,
			req_buf, sizeof(req_buf), &req_len,
			mock_rand_hex, rand_value
		);
	}
	);

	wbcrypto_sm2coop_sign_client_session_free(&sign_ctx);

}

void test_sm2coop_sign_respond_perf(
	wbcrypto_sm2coop_context* client,
	wbcrypto_sm2coop_context* server
) {
	uint64_t ret = 0;
	unsigned char msg_buf[] = "signature standard";
	unsigned char dgst_buf[1024] = { 0 };
	size_t dgst_len = 0;
	unsigned char req_buf[1024] = { 0 };
	size_t req_len = 0;
	unsigned char resp_buf[1024] = { 0 };
	size_t resp_len = 0;

	hex_to_binary(
		"304502205782622C1D736C2E715FE4670694E601D73F99996C40189F5466FE6317433143022100D0D536609E0706BD8DF53B4CFF4648193B9D5F0F7EDAA6E33BD4EE7CFEFFAE2E",
		req_buf,
		sizeof(req_buf)
	);
	req_len = 71;
	hex_to_binary(
		"DFF9985FE7C30071D5AF634F3859EC579FEDA441E9DF7C36B3813AAAE48728CE",
		dgst_buf,
		sizeof(dgst_buf)
	);
	dgst_len = 32;

	run_perf_test(
		"SM2Coop sign protocol / server_respond",
		1000, 1000,
		[&]() {
		wbcrypto_sm2coop_sign_server_respond(
			server,
			dgst_buf, dgst_len,
			req_buf, req_len,
			resp_buf, sizeof(resp_buf), &resp_len,
			mock_rand_hex, rand_value
		);
	}
	);

}

void test_sm2coop_sign_client_complete_perf(
	wbcrypto_sm2coop_context* client,
	wbcrypto_sm2coop_context* server
) {
	uint64_t ret = 0;
	unsigned char msg_buf[] = "signature standard";
	unsigned char sig_buf[1024] = { 0 };
	size_t sig_len = 0;
	unsigned char dgst_buf[1024] = { 0 };
	size_t dgst_len = 0;
	unsigned char req_buf[1024] = { 0 };
	size_t req_len = 0;
	unsigned char resp_buf[1024] = { 0 };
	size_t resp_len = 0;

	wbcrypto_sm2coop_sign_client_session sign_ctx;
	wbcrypto_sm2coop_sign_client_session_init(&sign_ctx);

	wbcrypto_sm2coop_sign_client_start(
		client,
		&sign_ctx,
		msg_buf, sizeof(msg_buf) - 1,
		dgst_buf, sizeof(dgst_buf), &dgst_len,
		req_buf, sizeof(req_buf), &req_len,
		mock_rand_hex, rand_value
	);

	wbcrypto_sm2coop_sign_server_respond(
		server,
		dgst_buf, dgst_len,
		req_buf, req_len,
		resp_buf, sizeof(resp_buf), &resp_len,
		mock_rand_hex, rand_value
	);

	run_perf_test(
		"SM2Coop sign protocol / client_complete",
		1000, 1000,
		[&]() {
		wbcrypto_sm2coop_sign_client_complete(
			client,
			&sign_ctx,
			resp_buf, resp_len,
			sig_buf, sizeof(sig_buf), &sig_len
		);
	}
	);

	wbcrypto_sm2coop_sign_client_session_free(&sign_ctx);

}

void test_sm2coop_sign_perf(
	wbcrypto_sm2coop_context* client,
	wbcrypto_sm2coop_context* server
) {
	uint64_t ret = 0;
	unsigned char msg_buf[] = "signature standard";
	unsigned char sig_buf[1024] = { 0 };
	size_t sig_len = 0;
	unsigned char dgst_buf[1024] = { 0 };
	size_t dgst_len = 0;
	unsigned char req_buf[1024] = { 0 };
	size_t req_len = 0;
	unsigned char resp_buf[1024] = { 0 };
	size_t resp_len = 0;

	wbcrypto_sm2coop_sign_client_session sign_ctx;
	wbcrypto_sm2coop_sign_client_session_init(&sign_ctx);

	run_perf_test(
		"SM2Coop sign protocol",
		1000, 1000,
		[&]() {
		wbcrypto_sm2coop_sign_client_start(
			client,
			&sign_ctx,
			msg_buf, sizeof(msg_buf) - 1,
			dgst_buf, sizeof(dgst_buf), &dgst_len,
			req_buf, sizeof(req_buf), &req_len,
			mock_rand_hex, rand_value
		);

		wbcrypto_sm2coop_sign_server_respond(
			server,
			dgst_buf, dgst_len,
			req_buf, req_len,
			resp_buf, sizeof(resp_buf), &resp_len,
			mock_rand_hex, rand_value
		);

		wbcrypto_sm2coop_sign_client_complete(
			client,
			&sign_ctx,
			resp_buf, resp_len,
			sig_buf, sizeof(sig_buf), &sig_len
		);
	}
	);

	wbcrypto_sm2coop_sign_client_session_free(&sign_ctx);

}

int main() {
	int ret = 0;
	wbcrypto_sm2coop_context client, server;
	wbcrypto_sm2coop_context_init(&client);
	wbcrypto_sm2coop_context_init(&server);

	MBEDTLS_MPI_CHK(test_keygen(&client, &server));

	test_sm2coop_decrypt_client_start_perf(&client, &server);
	test_sm2coop_decrypt_server_respond_perf(&client, &server);
	test_sm2coop_decrypt_client_complete_perf(&client, &server);
	test_sm2coop_decrypt_perf(&client, &server);

	test_sm2coop_sign_client_start_perf(&client, &server);
	test_sm2coop_sign_respond_perf(&client, &server);
	test_sm2coop_sign_client_complete_perf(&client, &server);
	test_sm2coop_sign_perf(&client, &server);

cleanup:
	wbcrypto_sm2coop_context_free(&client);
	wbcrypto_sm2coop_context_free(&server);
	return ret;
}
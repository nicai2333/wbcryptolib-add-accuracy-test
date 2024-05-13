#include "string.h"
#include "keygen.h"
#include "asserts.h"


char rand_value[] = "4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F";


int test_load_default_group_works() {
	int ret = 0;
	mbedtls_ecp_group grp;
	(mbedtls_ecp_group_init(&grp));
	ASSERT_SUCCESS(wbcrypto_sm2coop_load_default_group(&grp));
cleanup:
	return ret;
}

int test_load_default_group_handles_null() {
	int ret = 0;
	ASSERT_ERROR(wbcrypto_sm2coop_load_default_group(NULL));
cleanup:
	return ret;
}


int test_init_context_works() {
	int ret = 0;
	wbcrypto_sm2coop_context ctx;
	(wbcrypto_sm2coop_context_init(&ctx));
	USE_CLEANUP
cleanup:
	wbcrypto_sm2coop_context_free(&ctx);
	return ret;
}


int test_copy_context_works(wbcrypto_sm2coop_context* realFrom) {
	int ret = 0;
	wbcrypto_sm2coop_context to;
	(wbcrypto_sm2coop_context_init(&to));

	ASSERT_SUCCESS(wbcrypto_sm2coop_context_copy(realFrom, &to));

cleanup:
	wbcrypto_sm2coop_context_free(&to);
	return ret;
}

int test_copy_context_handles_null(wbcrypto_sm2coop_context* realFrom) {
	int ret = 0;
	wbcrypto_sm2coop_context to;
	wbcrypto_sm2coop_context_init(&to);

	ASSERT_ERROR_CODE(wbcrypto_sm2coop_context_copy(realFrom, NULL), WBCRYPTO_ERR_SM2COOP_BAD_INPUT_DATA);
	ASSERT_ERROR_CODE(wbcrypto_sm2coop_context_copy(NULL, &to), WBCRYPTO_ERR_SM2COOP_BAD_INPUT_DATA);
	ASSERT_ERROR_CODE(wbcrypto_sm2coop_context_copy(NULL, NULL), WBCRYPTO_ERR_SM2COOP_BAD_INPUT_DATA);

cleanup:
	wbcrypto_sm2coop_context_free(&to);
	return ret;
}


int test_free_context_works() {
	int ret = 0;
	wbcrypto_sm2coop_context ctx;
	wbcrypto_sm2coop_context_init(&ctx);

	wbcrypto_sm2coop_context_free(&ctx);
	USE_CLEANUP
cleanup:
	return ret;
}

int test_free_context_handles_null() {
	int ret = 0;
	wbcrypto_sm2coop_context_free(NULL);
	USE_CLEANUP
cleanup:
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
	
	ASSERT_SUCCESS(test_load_default_group_works());
	ASSERT_SUCCESS(test_load_default_group_handles_null());
	ASSERT_SUCCESS(test_init_context_works());
	ASSERT_SUCCESS(test_copy_context_works(&client));
	ASSERT_SUCCESS(test_copy_context_handles_null(&client));
	ASSERT_SUCCESS(test_free_context_works());
	ASSERT_SUCCESS(test_free_context_handles_null());

cleanup:
	wbcrypto_sm2coop_context_free(&client);
	wbcrypto_sm2coop_context_free(&server);
	return ret;
}
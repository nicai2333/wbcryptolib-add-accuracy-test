#include "wbcrypto/keybox_wbsm2.h"
#include "asserts.h"
#include "../hex_utils.h"
#include <string.h>

char rand_value[] = "4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F";

int keygen(
	wbcrypto_wbsm2_public_key* pubkey,
	wbcrypto_wbsm2_private_key_segment* segmentA,
	wbcrypto_wbsm2_private_key_segment* segmentB,
	char rand_value[65]
) {
	int ret = 0;

	ASSERT_SUCCESS(
		wbcrypto_wbsm2_generate_key(
			pubkey,
			segmentA, segmentB,
			mock_rand_hex, rand_value
		)
	);

cleanup:
	return ret;
}


int keybox_load_save_works(wbcrypto_keybox_wbsm2* facade) {
	int ret;
	wbcrypto_keybox_wbsm2 recovered;
	wbcrypto_keybox_wbsm2_init(&recovered);

	uint8_t key[16] = "FAFAFAFAFAFAFAFA";
	uint8_t buffer[512] = { 0 };

	size_t size = 0;
	ASSERT_SUCCESS(wbcrypto_keybox_wbsm2_save(facade, key, 16, buffer, sizeof(buffer), &size, WBCRYPTO_KEYBOX_WBSM2_ALL));

	ASSERT_SUCCESS(wbcrypto_keybox_wbsm2_load(&recovered, key, 16, buffer, size, WBCRYPTO_KEYBOX_WBSM2_ALL));

	ASSERT_SUCCESS(!(facade->loaded == recovered.loaded));
	ASSERT_SUCCESS(memcmp(facade->iv, recovered.iv, sizeof(recovered.iv)));
	ASSERT_SUCCESS(mbedtls_ecp_point_cmp(&facade->pubkey.P, &recovered.pubkey.P));
	ASSERT_SUCCESS(mbedtls_mpi_cmp_mpi(&facade->segmentA.hd, &recovered.segmentA.hd));
	ASSERT_SUCCESS(mbedtls_ecp_point_cmp(&facade->segmentA.W, &recovered.segmentA.W));
	ASSERT_SUCCESS(mbedtls_mpi_cmp_mpi(&facade->segmentB.hd, &recovered.segmentB.hd));
	ASSERT_SUCCESS(mbedtls_ecp_point_cmp(&facade->segmentB.W, &recovered.segmentB.W));

	ret = 0;
cleanup:
	wbcrypto_keybox_wbsm2_free(&recovered);
	return ret;
}

int main() {
	int ret;
	wbcrypto_keybox_wbsm2 keybox;
	wbcrypto_keybox_wbsm2_init(&keybox);

	keybox.loaded = WBCRYPTO_KEYBOX_WBSM2_ALL;
	memcpy(keybox.iv, "1234567890ABCDEF", 16);

	wbcrypto_wbsm2_load_default_group(&keybox.pubkey.grp);
	ASSERT_SUCCESS(keygen(&keybox.pubkey, &keybox.segmentA, &keybox.segmentB, rand_value));

	ASSERT_SUCCESS(keybox_load_save_works(&keybox));
cleanup:
	wbcrypto_keybox_wbsm2_free(&keybox);
	return ret;
}
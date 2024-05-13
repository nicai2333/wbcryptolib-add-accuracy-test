#include "wbcrypto/internal/keybox_wbsm2/keybox_wbsm2_asn1_read.h"
#include "wbcrypto/internal/keybox_wbsm2/keybox_wbsm2_asn1_write.h"
#include "asserts.h"
#include "../hex_utils.h"
#include <string.h>
#include "wbcrypto/internal/asn1_utils.h"

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


int keybox_works() {
	int ret;

	uint8_t iv_buffer[16] = "1234567890ABCDEF";
	uint8_t internal_buffer[16] = "fedcba0987654321";

	uint8_t buffer[512] = { 0 };
	uint8_t* p = buffer + sizeof(buffer) - 1;
	ASSERT_SUCCESS_NONNEG(
		wbcrypto_keybox_wbsm2_asn1_write_keybox(
			&p, buffer,
			iv_buffer, sizeof(iv_buffer),
			internal_buffer, sizeof(internal_buffer)
		)
	);

	wbcrypto_asn1_octetstring recovered_iv, recovered_internal;
	//now p is in place to read
	ASSERT_SUCCESS_NONNEG(
		wbcrypto_keybox_wbsm2_asn1_parse_keybox(
			&p, buffer + sizeof(buffer),
			&recovered_iv, &recovered_internal
		)
	);

	ASSERT_SUCCESS(memcmp(recovered_iv.p, iv_buffer, sizeof(iv_buffer)));
	ASSERT_SUCCESS(memcmp(recovered_internal.p, internal_buffer, sizeof(internal_buffer)));

	ret = 0;
cleanup:
	return ret;
}

int encrypted_keybox_works(wbcrypto_keybox_wbsm2* facade) {
	int ret;
	wbcrypto_keybox_wbsm2 recovered;
	wbcrypto_keybox_wbsm2_init(&recovered);
	
	uint8_t buffer[512] = { 0 };

	uint8_t* p = buffer + sizeof(buffer) - 1;
	ASSERT_SUCCESS_NONNEG(wbcrypto_keybox_wbsm2_asn1_write_encrypted_keybox(&p, buffer, facade, WBCRYPTO_KEYBOX_WBSM2_ALL));

	//p is now at beginning of the struct
	ASSERT_SUCCESS_NONNEG(wbcrypto_keybox_wbsm2_asn1_parse_encrypted_keybox(&p, buffer+sizeof(buffer), &recovered, WBCRYPTO_KEYBOX_WBSM2_ALL));

	ASSERT_SUCCESS(!(facade->loaded == recovered.loaded));
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

int public_key_works(wbcrypto_wbsm2_public_key* pubkey) {
	int ret;
	wbcrypto_wbsm2_public_key recovered;
	wbcrypto_wbsm2_public_key_init(&recovered);

	uint8_t buffer[512] = { 0 };

	uint8_t* p = buffer + sizeof(buffer) - 1;
	ASSERT_SUCCESS_NONNEG(wbcrypto_keybox_wbsm2_asn1_write_public_key(&p, buffer, pubkey));

	//p is now at beginning of the struct
	ASSERT_SUCCESS_NONNEG(wbcrypto_keybox_wbsm2_asn1_parse_public_key(&p, buffer + sizeof(buffer), &recovered));

	ASSERT_SUCCESS(mbedtls_ecp_point_cmp(&pubkey->P, &pubkey->P));

	ret = 0;
cleanup:
	wbcrypto_wbsm2_public_key_free(&recovered);
	return ret;
}

int private_key_segment_works(wbcrypto_wbsm2_private_key_segment* segmentA) {
	int ret;
	wbcrypto_wbsm2_private_key_segment recovered;
	wbcrypto_wbsm2_private_key_segment_init(&recovered);
	
	uint8_t buffer[512] = { 0 };

	uint8_t* p = buffer + sizeof(buffer) - 1;
	ASSERT_SUCCESS_NONNEG(wbcrypto_keybox_wbsm2_asn1_write_private_key_segment(&p, buffer, WBCRYPTO_KEYBOX_WBSM2_PRIVATE_SEGMENT_A, segmentA));

	//p is now at beginning of the struct
	ASSERT_SUCCESS_NONNEG(wbcrypto_keybox_wbsm2_asn1_parse_private_key_segment(&p, buffer + sizeof(buffer), WBCRYPTO_KEYBOX_WBSM2_PRIVATE_SEGMENT_A, &recovered));

	ASSERT_SUCCESS(mbedtls_mpi_cmp_mpi(&segmentA->hd, &recovered.hd));
	ASSERT_SUCCESS(mbedtls_ecp_point_cmp(&segmentA->W, &recovered.W));
	
	ret = 0;
cleanup:
	wbcrypto_wbsm2_private_key_segment_free(&recovered);
	return ret;
}

int algorithm_identifer_works() {
	int ret;
	uint8_t buffer[64] = { 0 };

	uint8_t* p = buffer + sizeof(buffer) - 1;
	ASSERT_SUCCESS_NONNEG(wbcrypto_keybox_wbsm2_asn1_write_algorithm_identifer(&p, buffer));

	//p is now at beginning of the struct
	ASSERT_SUCCESS_NONNEG(wbcrypto_keybox_wbsm2_asn1_assert_algorithm_identifer(&p, buffer + sizeof(buffer)));

	ret = 0;
cleanup:
	return ret;
}

int ec_parameter_works() {
	int ret;
	uint8_t buffer[64] = { 0 };
	
	uint8_t* p = buffer + sizeof(buffer) - 1;
	ASSERT_SUCCESS_NONNEG(wbcrypto_keybox_wbsm2_asn1_write_ec_parameter(&p, buffer));
	
	//p is now at beginning of the struct
	ASSERT_SUCCESS_NONNEG(wbcrypto_keybox_wbsm2_asn1_assert_ec_parameter(&p, buffer + sizeof(buffer)));
	
	ret = 0;
cleanup:
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
	
	ASSERT_SUCCESS(keybox_works());
	ASSERT_SUCCESS(encrypted_keybox_works(&keybox));
	ASSERT_SUCCESS(public_key_works(&keybox.pubkey));
	ASSERT_SUCCESS(private_key_segment_works(&keybox.segmentA));
	ASSERT_SUCCESS(algorithm_identifer_works());
	ASSERT_SUCCESS(ec_parameter_works());
 cleanup:
	wbcrypto_keybox_wbsm2_free(&keybox);
	return ret;
}
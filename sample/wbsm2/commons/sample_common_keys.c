#include "sample_common_keys.h"

#define ASSERT_SUCCESS(func)       \
    do                           \
    {                            \
        if( ( ret = (func) ) != 0 ) \
            goto cleanup;        \
    } while( 0 )

//the public key part of WBSM2
wbcrypto_wbsm2_public_key pubkey;
//the private keys
wbcrypto_wbsm2_private_key_segment segmentA, segmentB;

int load_public_key(wbcrypto_wbsm2_public_key* public_key) {
	int ret;
	ASSERT_SUCCESS(wbcrypto_wbsm2_load_default_group(&public_key->grp));
	ASSERT_SUCCESS(mbedtls_mpi_read_string(
		&public_key->P.X, 16,
		"1587FB3DBB3BCFC06BAE3280B17950FF494F749BE06DA0567C26997FA0234776"
	));
	ASSERT_SUCCESS(mbedtls_mpi_read_string(
		&public_key->P.Y, 16,
		"0E1D447879BE7F29E16BEE533C68EF9C8BE6DE7A67844E515937F0B32A621A01"
	));
	ASSERT_SUCCESS(mbedtls_mpi_read_string(&public_key->P.Z, 16, "01"));
cleanup:
	return ret;
}

int load_private_key_segmentA(wbcrypto_wbsm2_private_key_segment* segmentA) {
	int ret;
	ASSERT_SUCCESS(mbedtls_mpi_read_string(
		&segmentA->hd, 16,
		"3231C3DF7DD40ED1B468E75BD2A324D979078FF74BA6B16E4063337066501974"
	));
	ASSERT_SUCCESS(mbedtls_mpi_read_string(
		&segmentA->W.X, 16,
		"98222684C68160750AA50687448ADAAB641BA256518DC3BE5B34E6A285936BA4"
	));
	ASSERT_SUCCESS(mbedtls_mpi_read_string(
		&segmentA->W.Y, 16,
		"06D3C6A4F26E56F87B9EC559F9CA1B1D5FD7B9DB381E6A1A2E954C8EBABDB311"
	));
	ASSERT_SUCCESS(mbedtls_mpi_read_string(&segmentA->W.Z, 16, "01"));
cleanup:
	return ret;
}

int load_private_key_segmentB(wbcrypto_wbsm2_private_key_segment* segmentB) {
	int ret;
	ASSERT_SUCCESS(mbedtls_mpi_read_string(
		&segmentB->hd, 16,
		"D7867B0BDD2D9E3994E451ADC0F3D4BF0A336CD58B5705899CF8F096C1706C94"
	));
	ASSERT_SUCCESS(mbedtls_mpi_read_string(
		&segmentB->W.X, 16,
		"DA5EC5C6DE7E2976F953A6922F9C01B15C6442CDEFD06E2F9541547B813934FD"
	));
	ASSERT_SUCCESS(mbedtls_mpi_read_string(
		&segmentB->W.Y, 16,
		"308FF39DDCEBC401CAC59372318C6A99A2F52797DC9F5CE665864B4A4264421D"
	));
	ASSERT_SUCCESS(mbedtls_mpi_read_string(&segmentB->W.Z, 16, "01"));
cleanup:
	return ret;
}


int setup_wbsm2_keys() {
	int ret;

	//we do basic context initialization......
	wbcrypto_wbsm2_public_key_init(&pubkey);
	wbcrypto_wbsm2_private_key_segment_init(&segmentA);
	wbcrypto_wbsm2_private_key_segment_init(&segmentB);

	//load the keys
	ASSERT_SUCCESS(load_public_key(&pubkey));
	ASSERT_SUCCESS(load_private_key_segmentA(&segmentA));
	ASSERT_SUCCESS(load_private_key_segmentB(&segmentB));

cleanup:
	return ret;
}

void teardown_wbsm2_keys() {
	wbcrypto_wbsm2_private_key_segment_init(&segmentB);
	wbcrypto_wbsm2_private_key_segment_init(&segmentA);
	wbcrypto_wbsm2_public_key_free(&pubkey);
}
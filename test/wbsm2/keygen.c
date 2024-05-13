#include "keygen.h"
#include "asserts.h"
#include "../hex_utils.h"


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

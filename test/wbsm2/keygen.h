#ifndef WBCRYPTO_SM2COOP_TEST_KEYGEN_H_
#define WBCRYPTO_SM2COOP_TEST_KEYGEN_H_

#include "wbcrypto/wbsm2.h"

int keygen(
	wbcrypto_wbsm2_public_key* pubkey,
	wbcrypto_wbsm2_private_key_segment* segmentA,
	wbcrypto_wbsm2_private_key_segment* segmentB,
	char rand_value[65]
);

#endif
#ifndef WBCRYPTO_SM2COOP_TEST_KEYGEN_H_
#define WBCRYPTO_SM2COOP_TEST_KEYGEN_H_

#include "wbcrypto/sm2coop.h"

int keygen(wbcrypto_sm2coop_context* client_key, wbcrypto_sm2coop_context* server_key, char rand_value[65]);

#endif
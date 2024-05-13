//
// Created by libin on 2023/5/21.
//

#ifndef WBCRYPTO_KEYGEN_H
#define WBCRYPTO_KEYGEN_H

#include "wbcrypto/sm2coop.h"

int keygen(wbcrypto_sm2coop_context* client_key, wbcrypto_sm2coop_context* server_key, char rand_value[65]);

#endif //WBCRYPTO_KEYGEN_H

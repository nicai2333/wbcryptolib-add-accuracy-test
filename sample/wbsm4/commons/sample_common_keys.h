/*
 * @Author: RyanCLQ
 * @Date: 2023-05-28 12:45:52
 * @LastEditors: RyanCLQ
 * @LastEditTime: 2023-05-30 09:57:25
 * @Description: 请填写简介
 */
#ifndef WBCRYPTO_SAMPLE_COMMON_KEYS_H_
#define WBCRYPTO_SAMPLE_COMMON_KEYS_H_

#include "wbcrypto/wbsm4.h"
#include "wbcrypto/wbsm4_generator.h"
//the sm4 whitebox table context for encryption
extern wbcrypto_wbsm4_context  enc_ctx;

//the sm4 whitebox table context for decryption
extern wbcrypto_wbsm4_context  dec_ctx;

//setup the keys, return non-zero value on failure
int setup_wbsm4_keys();


#endif // WBCRYPTO_SAMPLE_COMMON_KEYS_H_
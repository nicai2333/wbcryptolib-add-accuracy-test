/*
 * @Author: RyanCLQ
 * @Date: 2023-06-13 22:14:50
 * @LastEditors: RyanCLQ
 * @LastEditTime: 2023-06-18 15:29:15
 * @Description: 请填写简介
 */
#include "crypto/speed_test.h"

int main(){
    wbcrypto_block_cipher_speed_test(WBSM4_XL, ECB, 1);
    wbcrypto_block_cipher_speed_test(WBSM4_XL_LA, ECB, 1);
    // wbcrypto_block_cipher_speed_test(WBAES_CEJO, ECB, 8);
    // wbcrypto_block_cipher_speed_test(WBAES_CEJO, CBC, 8);
    // wbcrypto_block_cipher_speed_test(WBAES_CEJO, CTR, 4);
    // wbcrypto_block_cipher_speed_test(WBSM4_SE, GCM, 16);
    // wbcrypto_block_cipher_speed_test(WBSM4_SE, ECB, 8);
    // wbcrypto_block_cipher_speed_test(WBSM4_SE, CBC, 8);
    // wbcrypto_block_cipher_speed_test(WBSM4_SE, CTR, 4);
    // wbcrypto_block_cipher_speed_test(WBSM4_XL_LA, GCM, 16);
    // wbcrypto_block_cipher_speed_test(WBSM4_XL_LA, ECB, 2);
    // wbcrypto_block_cipher_speed_test(WBSM4_XL_LA, CBC, 8);
    // wbcrypto_block_cipher_speed_test(WBSM4_XL_LA, CTR, 1);
    return 0;
}
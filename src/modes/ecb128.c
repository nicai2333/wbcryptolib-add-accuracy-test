/*
 * @Author:
 * @Date: 2023/5/28 15:34
 * @Description:
 */
#include "modes_lcl.h"
#include <string.h>
#include <assert.h>
void WBCRYPTO_ecb128_encrypt(const unsigned char *in, unsigned char *out, size_t len, const void *key, WBCRYPTO_block128_f block){
    assert (len % 16 == 0);
    while (len) {
        (*block)(in, out, key);
        len -= 16;
        in += 16;
        out += 16;
    }
}
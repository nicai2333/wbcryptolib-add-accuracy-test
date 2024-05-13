#include "modes_lcl.h"
#include <string.h>

#if !defined(STRICT_ALIGNMENT) && !defined(PEDANTIC)
# define STRICT_ALIGNMENT 0
#endif

void WBCRYPTO_cbc128_encrypt(const unsigned char *in, unsigned char *out,
                             size_t len, const void *key,
                             unsigned char *_iv, WBCRYPTO_block128_f block)
{
    size_t n;
    const unsigned char *iv = _iv;
    while (len) {
        if (len >= 16) {
            for (n = 0; n < 16 && n < len; ++n)
                out[n] = in[n] ^ iv[n];
            for (; n < 16; ++n)
                out[n] = iv[n];
            (*block)(out, out, key);
            iv = out;
            if (len <= 16)
                break;
            len -= 16;
            in += 16;
            out += 16;
        }
        else{
            n = 0;
            while(len){
                out[n] = in[n];
                n++;
                len--;
            }
        }
    }
}

void WBCRYPTO_cbc128_decrypt(const unsigned char *in, unsigned char *out,
                             size_t len, const void *key,
                             unsigned char *_iv, WBCRYPTO_block128_f block)
{
     unsigned char ivec[16];
     memcpy(ivec, _iv, 16);
    size_t n;
    union {
        size_t t[16 / sizeof(size_t)];
        unsigned char c[16];
    } tmp;

    while (len) {
        if (len >= 16) {
            unsigned char c;
            (*block)(in, tmp.c, key);
            for (n = 0; n < 16 && n < len; ++n) {
                c = in[n];
                out[n] = tmp.c[n] ^ ivec[n];
                ivec[n] = c;
            }
            if (len <= 16) {
                for (; n < 16; ++n)
                    ivec[n] = in[n];
                break;
            }
            len -= 16;
            in += 16;
            out += 16;
        }
        else{
            n = 0;
            while(len){
                out[n] = in[n];
                n++;
                len--;

            }
        }
    }

}

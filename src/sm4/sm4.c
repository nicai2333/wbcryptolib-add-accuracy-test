
#include "crypto/sm4.h"
#include "stdint.h"
#include <string.h>
/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n,b,i)                             \
{                                                       \
    (n) = ( (unsigned long) (b)[(i)    ] << 24 )        \
        | ( (unsigned long) (b)[(i) + 1] << 16 )        \
        | ( (unsigned long) (b)[(i) + 2] <<  8 )        \
        | ( (unsigned long) (b)[(i) + 3]       );       \
}
#endif

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n,b,i)                             \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

/*
 *rotate shift left marco definition
 *
 */
#define  SHL(x,n) (((x) & 0xFFFFFFFF) << n)
#define ROTL(x,n) (SHL((x),n) | ((x) >> (32 - n)))

static const unsigned char SboxTable[16][16] =
        {
                {0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05},
                {0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99},
                {0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62},
                {0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6},
                {0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8},
                {0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35},
                {0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87},
                {0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e},
                {0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1},
                {0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3},
                {0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f},
                {0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51},
                {0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8},
                {0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0},
                {0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84},
                {0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48}
        };
static const unsigned long CK[32] =
        {
                0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
                0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
                0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
                0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
                0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
                0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
                0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
                0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
        };

static unsigned char sm4Sbox(unsigned char inch)
{
    unsigned char *pTable = (unsigned char *)SboxTable;
    unsigned char retVal = (unsigned char)(pTable[inch]);
    return retVal;
}
static uint32_t sm4Lt(uint32_t ka)
{
    uint32_t bb = 0;
    uint32_t c = 0;
    unsigned char a[4];
    unsigned char b[4];
    PUT_ULONG_BE(ka, a, 0)
    b[0] = sm4Sbox(a[0]);
    b[1] = sm4Sbox(a[1]);
    b[2] = sm4Sbox(a[2]);
    b[3] = sm4Sbox(a[3]);
    GET_ULONG_BE(bb, b, 0)
    c = bb ^ (ROTL(bb, 2)) ^ (ROTL(bb, 10)) ^ (ROTL(bb, 18)) ^ (ROTL(bb, 24));
    return c;
}


static uint32_t sm4F(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3, uint32_t rk)
{
    return (x0 ^ sm4Lt(x1 ^ x2 ^ x3 ^ rk));
}

void wbcrypto_sm4_encrypt(const unsigned char *in, unsigned char *out, const wbcrypto_sm4_context *ctx){
    uint32_t i = 0;
    uint32_t ulbuf[36];

    memset(ulbuf, 0, sizeof(ulbuf));
    GET_ULONG_BE( ulbuf[0], in, 0 )
    GET_ULONG_BE( ulbuf[1], in, 4 )
    GET_ULONG_BE( ulbuf[2], in, 8 )
    GET_ULONG_BE( ulbuf[3], in, 12 )
    while (i < 32)
    {
        ulbuf[i + 4] = sm4F(ulbuf[i], ulbuf[i + 1], ulbuf[i + 2], ulbuf[i + 3], ctx->sk[i]);
        i++;
    }
    PUT_ULONG_BE(ulbuf[35], out, 0);
    PUT_ULONG_BE(ulbuf[34], out, 4);
    PUT_ULONG_BE(ulbuf[33], out, 8);
    PUT_ULONG_BE(ulbuf[32], out, 12);

}

#include "crypto/sm4.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>
/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n,b,i)                             \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )        \
        | ( (uint32_t) (b)[(i) + 1] << 16 )        \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )        \
        | ( (uint32_t) (b)[(i) + 3]       );       \
}
#endif

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n,b,i)                             \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

/*
 *rotate shift left marco definition
 *
 */
#define  SHL(x,n) (((x) & 0xFFFFFFFF) << n)
#define ROTL(x,n) (SHL((x),n) | ((x) >> (32 - n)))

#define SWAP(a,b) { uint32_t t = a; a = b; b = t; t = 0; }


/* System parameter */
static const uint32_t FK[4] = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};


/* private function:
 * Calculating round encryption key.
 * args:    [in] a: a is a 32 bits unsigned value;
 * return: sk[i]: i{0,1,2,3,...31}.
 */
static uint32_t sm4CalciRK(uint32_t ka)
{
    uint32_t bb = 0;
    uint32_t rk = 0;
    unsigned char a[4];
    unsigned char b[4];
    PUT_ULONG_BE(ka, a, 0)
    b[0] = sm4Sbox(a[0]);
    b[1] = sm4Sbox(a[1]);
    b[2] = sm4Sbox(a[2]);
    b[3] = sm4Sbox(a[3]);
    GET_ULONG_BE(bb, b, 0)
    rk = bb ^ (ROTL(bb, 13)) ^ (ROTL(bb, 23));
    return rk;
}

static void sm4_setkey( uint32_t SK[32], unsigned char key[16] )
{
    uint32_t MK[4];
    uint32_t k[36];
    uint32_t i = 0;

    GET_ULONG_BE( MK[0], key, 0 );
    GET_ULONG_BE( MK[1], key, 4 );
    GET_ULONG_BE( MK[2], key, 8 );
    GET_ULONG_BE( MK[3], key, 12 );
    k[0] = MK[0] ^ FK[0];
    k[1] = MK[1] ^ FK[1];
    k[2] = MK[2] ^ FK[2];
    k[3] = MK[3] ^ FK[3];
    for (; i < 32; i++)
    {
        k[i + 4] = k[i] ^ (sm4CalciRK(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]));
        SK[i] = k[i + 4];
    }

}

/*
 * SM4 key schedule (128-bit, encryption)
 */

void wbcrypto_sm4_setkey_enc( wbcrypto_sm4_context *ctx, const unsigned char key[16] )
{
    sm4_setkey( ctx->sk, key );
}

/*
 * SM4 key schedule (128-bit, decryption)
 */
void wbcrypto_sm4_setkey_dec( wbcrypto_sm4_context *ctx, const unsigned char key[16] )
{
    int i;
    sm4_setkey( ctx->sk, key );
    for ( i = 0; i < 16; i ++ )
    {
        SWAP( ctx->sk[ i ], ctx->sk[ 31 - i] );
    }
}

void wbcrypto_sm4_free(wbcrypto_sm4_context *ctx)
{
    memset( ctx, 0, sizeof(wbcrypto_sm4_context) );
    if(ctx!=NULL){
        free(ctx);
        ctx=NULL;
    }
}
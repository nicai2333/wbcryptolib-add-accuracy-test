/*
 * @Descripttion : 
 * @Version      : 
 * @Autor        : one30
 * @Date         : 2020-11-11 21:52:20
 * @LastEditTime : 2021-02-21 20:02:05
 * @FilePath     : /include/sm4_bs256.h
 */

#ifndef WBCRYPTO_SM4_BS_H
#define WBCRYPTO_SM4_BS_H

#include <stdio.h>
#include <stdint.h>	
#include <string.h>
#include <immintrin.h>
#include "crypto/sm4_bs_mode_gcm.h"
#include "crypto/speed.h"

#define MIN(X,Y) ((X) < (Y) ? (X) : (Y))
#define MAX(X,Y) ((X) > (Y) ? (X) : (Y))
#define BLOCK_SIZE          128
#define WORD_SIZE           256
#define BS_BLOCK_SIZE       4096
#define SM4_CTR_TESTS_BYTES 64

#define _mm256_set_m128i(v0, v1)  _mm256_insertf128_si256(_mm256_castsi128_si256(v1), (v0), 1)
#define _mm256_setr_m128i(v0, v1) _mm256_set_m128i((v1), (v0))
typedef __m256i bit_t;//__m256i bit_t;
typedef struct {
  bit_t b0;
  bit_t b1;
  bit_t b2;
  bit_t b3;
  bit_t b4;
  bit_t b5;
  bit_t b6;
  bit_t b7;
} bits;

#if defined(WBCRYPTO_SM4_BS_512)
    #define BS512_BLOCK_SIZE       8192
    typedef struct {
    __m512i b0;
    __m512i b1;
    __m512i b2;
    __m512i b3;
    __m512i b4;
    __m512i b5;
    __m512i b6;
    __m512i b7;
    } bits_512;
    void sm4_bs512_ecb_encrypt(uint8_t* outputb,uint8_t* inputb,int size,__m512i (*rk)[32]);
    void sm4_bs512_ctr_encrypt(uint8_t * outputb, uint8_t * inputb, int size, __m256i (*rk)[32], uint8_t * iv);
    void sm4_bs512_gcm_encrypt(uint8_t *outputb, uint8_t *inputb, int size,
        __m512i (*rk)[32], uint8_t *iv, int iv_len, uint8_t *add ,int add_len,
        uint8_t *tag, int tag_len, gcm_context *ctx);
    void sm4_bs512_gcm_init(gcm_context *context, unsigned char *key,
    __m512i (*BS_RK_512)[32], unsigned char *iv);
    void sm4_bs512_key_schedule(uint8_t* key, __m512i (*BS_RK_512)[32]);
    void Sm4_BS512_BoolFun(bits_512 in, __m512i *out0, __m512i *out1, __m512i *out2, __m512i *out3, __m512i *out4, __m512i *out5, __m512i *out6, __m512i *out7);
    void BS512_iteration(__m512i* N, __m512i BS_RK_512[32][32]);
    void Sbox_BS512(int round,__m512i buf_512[36][32]);
    void BS_TRANS2_128x512(__m128i* M,__m512i* N);
    void BS_TRANS2_VER_128x512(__m512i* N,__m128i* M);
#endif


/**
 * @brief A constant-time method to zero a block of memory.
 * 
 * @param ptr the pointer of memory location to be zeroed
 * @param size the size of the memory block in bytes
 */
void crypto_memzero(void const* ptr, const size_t size);

void hi();
uint64_t start_rdtsc();
uint64_t end_rdtsc();
void benchmark_sm4_bs_ecb_encrypt(uint8_t *plain, uint8_t *cipher,int size,__m256i (*rk)[32]);
void benchmark_sm4_bs_ctr_encrypt(uint8_t *plain, uint8_t *cipher,int size,__m256i (*rk)[32],uint8_t * iv);
void benchmark_sm4_bs_gcm_encrypt(uint8_t *plain, uint8_t *cipher,int size,__m256i (*rk)[32],
    uint8_t * iv, int iv_len, uint8_t *add ,int add_len,
    uint8_t *tag, int tag_len, uint8_t T[][256][16]);
void sm4_bs256_ecb_encrypt(uint8_t* outputb,uint8_t* inputb,int size,__m256i (*rk)[32]);

void sm4_bs256_ctr_encrypt(uint8_t * outputb, uint8_t * inputb, int size, __m256i (*rk)[32], uint8_t * iv);

void sm4_bs256_gcm_encrypt(uint8_t *outputb, uint8_t *inputb, int size,
    __m256i (*rk)[32], uint8_t *iv, int iv_len, uint8_t *add ,int add_len,
    uint8_t *tag, int tag_len, gcm_context *ctx);
void sm4_bs256_gcm_init(gcm_context *context, unsigned char *key,
__m256i (*BS_RK_256)[32], unsigned char *iv);

void sm4_bs256_key_schedule(uint8_t* key, __m256i (*BS_RK_256)[32]);

void BS_init_M(__m128i* M);
void SM4_BS_enc(__m128i* M,__m256i* N);
// void SM4_BS_enc();
void BS_TRANS();
void BS_TRANS_128x256(__m128i* M,__m256i* N);
void BS_TRANS_inv();
void BS_TRANS_VER_128x256(__m256i* N,__m128i* M);
static unsigned long sm4CalciRK(unsigned long ka);
static unsigned char sm4Sbox(unsigned char inch);
void Sm4_BoolFun(bits in, bit_t *out0, bit_t *out1, bit_t *out2, bit_t *out3, bit_t *out4, bit_t *out5, bit_t *out6, bit_t *out7);

void BS_iteration(__m256i* N,__m256i (*BS_RK_256)[32]);

void S_box(int round,__m256i (*buf_256)[32]);

void BS_TRANS_128x128(__m128i* M,__m128i* N);

void sm4_bs256_ecb(uint8_t *output, uint8_t *input, int size, uint8_t *key_vector);
void sm4_bs256_ctr(uint8_t *output, uint8_t *input, int size, uint8_t *key_vector, uint8_t *iv);
void sm4_bs256_gcm(uint8_t *output, uint8_t *input, int size, uint8_t *key_vector, int key_len, uint8_t *iv, int iv_len, uint8_t *tag, int tag_len, uint8_t *Associated_Data, int add_len);
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

#define SWAP(a,b) { uint64_t t = a; a = b; b = t; t = 0; }

#endif
#ifndef WBCRYPTO_SM4_BS_RO_H
#define WBCRYPTO_SM4_BS_RO_H

#define WBCRYPTO_SM4_BS_RO_256
// #define WBCRYPTO_SM4_BS_RO_512
// #define WBCRYPTO_SM4_BS_RO_NEON

#include <stdio.h>
#include <stdint.h>	
#include <string.h>
#include "crypto/sm4_bs_mode_gcm.h"
#include "crypto/speed.h"

#if defined(WBCRYPTO_SM4_BS_RO_NEON)
    #include <arm_neon.h>
#else
    #include <immintrin.h>
#endif

#define MIN(X,Y) ((X) < (Y) ? (X) : (Y))
#define MAX(X,Y) ((X) > (Y) ? (X) : (Y))
#define BLOCK_SIZE          128
#define WORD_SIZE           256
#define BS_BLOCK_SIZE       4096
#define SM4_CTR_TESTS_BYTES 64
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

#if defined(WBCRYPTO_SM4_BS_RO_256)
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

    void sm4_bsro256_key_schedule(uint8_t* key, uint8_t BS_RK[32][8][32]);
    void sm4_bsro256_ecb_encrypt(uint8_t* outputb,uint8_t* inputb,int size,uint8_t rk[32][8][32]);
    void sm4_bsro256_ctr_encrypt(uint8_t * outputb, uint8_t * inputb, int size, uint8_t rk [32][8][32], uint8_t * iv);
    void sm4_bsro256_gcm_init(gcm_context *context, unsigned char *key, uint8_t rk [32][8][32], unsigned char *iv);
    void sm4_bsro256_gcm_encrypt(uint8_t *outputb, uint8_t *inputb, int size,
        uint8_t rk [32][8][32], uint8_t *iv, int iv_len, uint8_t *add ,int add_len,
        uint8_t *tag, int tag_len, gcm_context *ctx);


    void benchmark_sm4_bs_ro_256_ecb_encrypt(uint8_t *plain, uint8_t *cipher,int size,uint8_t rk[32][8][32]);
    void benchmark_sm4_bs_ro_256_ctr_encrypt(uint8_t *plain, uint8_t *cipher,int size,uint8_t rk[32][8][32],uint8_t * iv);
    void benchmark_sm4_bs_ro_256_gcm_encrypt(uint8_t *plain, uint8_t *cipher,int size,uint8_t rk[32][8][32],
        uint8_t * iv, int iv_len, uint8_t *add ,int add_len,
        uint8_t *tag, int tag_len, uint8_t T[][256][16]);

    static unsigned long sm4CalciRK(unsigned long ka);
    static unsigned char sm4Sbox(unsigned char inch);
    static void Sm4_BoolFun(bits in, bit_t *out0, bit_t *out1, bit_t *out2, bit_t *out3, bit_t *out4, bit_t *out5, bit_t *out6, bit_t *out7);

    static void BS_iteration(uint8_t* N,uint8_t BS_RK_256 [32][8][32]);

    static void S_box(__m256i *buf_256);

    static void L_tran(__m256i *buf_256);
    static __m256i L_shuffle(__m256i data, int move);

    static void BS_TRANS_128x128(__m128i* M,__m128i* N);

    void sm4_bsro256_ecb(uint8_t *output, uint8_t *input, int size, uint8_t *key_vector);
    void sm4_bsro256_ctr(uint8_t *output, uint8_t *input, int size, uint8_t *key_vector, uint8_t *iv);
    void sm4_bsro256_gcm(uint8_t *output, uint8_t *input, int size, uint8_t *key_vector, int key_len, uint8_t *iv, int iv_len, uint8_t *tag, int tag_len, uint8_t *Associated_Data, int add_len);
    //void TEST_sm4_bsro256_key_schedule(uint8_t* key, uint8_t BS_RK [32][8][32]);
    void performance_test_sm4_bsro256();

    size_t test_sm4_bsro256_ecb_crypt_loop(size_t size);                          
    size_t test_sm4_bsro256_ctr_crypt_loop(size_t size); 
    size_t test_sm4_bsro256_gcm_crypt_loop(size_t size); 
#endif

#if defined(WBCRYPTO_SM4_BS_RO_512)
    #define _mm512_setr_epi8(v63, v62 ,v61, v60, v59, v58, v57, v56, v55, v54,          \
                            v53, v52, v51, v50, v49, v48, v47, v46, v45, v44,           \
                            v43, v42, v41, v40, v39, v38, v37, v36, v35, v34,           \
                            v33, v32, v31, v30, v29, v28, v27, v26, v25, v24,           \
                            v23, v22, v21, v20, v19, v18, v17, v16, v15, v14,           \
                            v13, v12, v11, v10, v9, v8, v7, v6, v5, v4, v3, v2, v1, v0) \
            _mm512_set_epi8(v0, v1 ,v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, \
                            v14, v15, v16, v17, v18, v19, v20, v21, v22, v23,           \
                            v24, v25, v26, v27, v28, v29, v30, v31, v32, v33,           \
                            v34, v35, v36, v37, v38, v39, v40, v41, v42, v43,           \
                            v44, v45, v46, v47, v48, v49, v50, v51, v52, v53,           \
                            v54, v55, v56, v57, v58, v59, v60, v61, v62, v63)           
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
    void sm4_bsro512_ecb_encrypt(uint8_t* outputb,uint8_t* inputb,int size,uint8_t rk[32][8][64]);
    void sm4_bsro512_ctr_encrypt(uint8_t * outputb, uint8_t * inputb, int size, uint8_t rk[32][8][64], uint8_t * iv);
    void sm4_bsro512_gcm_encrypt(uint8_t *outputb, uint8_t *inputb, int size,
        uint8_t rk[32][8][64], uint8_t *iv, int iv_len, uint8_t *add ,int add_len,
        uint8_t *tag, int tag_len, gcm_context *ctx);
    void sm4_bsro512_gcm_init(gcm_context *context, unsigned char *key,
    uint8_t BS_RK_512[32][8][64], unsigned char *iv);
    void sm4_bsro512_key_schedule(uint8_t* key, uint8_t BS_RK_512[32][8][64]);
    void Sm4_BSRO512_BoolFun(bits_512 in, __m512i *out0, __m512i *out1, __m512i *out2, __m512i *out3, __m512i *out4, __m512i *out5, __m512i *out6, __m512i *out7);
    void BSRO512_iteration(__m512i* N, __m512i BS_RK_512[32][8]);
    void Sbox_BSRO512(__m512i buf_512[8]);

    void performance_test_sm4_bsro512();
    size_t test_sm4_bsro512_ecb_crypt_loop(size_t size);                          
    size_t test_sm4_bsro512_ctr_crypt_loop(size_t size); 
    size_t test_sm4_bsro512_gcm_crypt_loop(size_t size); 
    void benchmark_sm4_bs_ro_512_ecb_encrypt(uint8_t *plain, uint8_t *cipher,int size,uint8_t rk[32][8][64]);
    void benchmark_sm4_bs_ro_512_ctr_encrypt(uint8_t *plain, uint8_t *cipher,int size,uint8_t rk[32][8][64],uint8_t * iv);
    void benchmark_sm4_bs_ro_512_gcm_encrypt(uint8_t *plain, uint8_t *cipher,int size,uint8_t rk[32][8][64],
        uint8_t * iv, int iv_len, uint8_t *add ,int add_len,
        uint8_t *tag, int tag_len, uint8_t T[][256][16]);
#endif

#if defined(WBCRYPTO_SM4_BS_RO_NEON)
    
    typedef union {
    uint8x16_t vect_u8;
    uint16x8_t vect_u16;
    uint32x4_t vect_u32;
    uint64x2_t vect_u64;
    } __m128i;

    typedef struct {
    __m128i b0;
    __m128i b1;
    __m128i b2;
    __m128i b3;
    __m128i b4;
    __m128i b5;
    __m128i b6;
    __m128i b7;
    } bits_neon;
    void sm4_bsro_neon_ecb_encrypt(uint8_t* outputb,uint8_t* inputb,int size,uint8_t rk[32][8][16]);
    void sm4_bsro_neon_ctr_encrypt(uint8_t * outputb, uint8_t * inputb, int size, uint8_t rk[32][8][16], uint8_t * iv);
    void sm4_bsro_neon_gcm_encrypt(uint8_t *outputb, uint8_t *inputb, int size,
        uint8_t rk[32][8][16], uint8_t *iv, int iv_len, uint8_t *add ,int add_len,
        uint8_t *tag, int tag_len, gcm_context *ctx);
    void sm4_bsro_neon_gcm_init(gcm_context *context, unsigned char *key,
    uint8_t BS_RK_NEON[32][8][16], unsigned char *iv);
    void sm4_bsro_neon_key_schedule(uint8_t* key, uint8_t BS_RK_NEON[32][8][16]);
    void Sm4_BSRO_NEON_BoolFun(bits_neon in, __m128i buf[8]);
    void BSRO_NEON_iteration(__m128i* N, __m128i BS_RK_NEON[32][8]);
    void Sbox_BSRO_NEON(__m128i buf_neon[8]);

    void performance_test_sm4_bsro_neon();
    size_t test_sm4_bsro_neon_ecb_crypt_loop(size_t size);                          
    size_t test_sm4_bsro_neon_ctr_crypt_loop(size_t size); 
    size_t test_sm4_bsro_neon_gcm_crypt_loop(size_t size); 
    void benchmark_sm4_bs_ro_neon_ecb_encrypt(uint8_t *plain, uint8_t *cipher,int size,uint8_t rk[32][8][16]);
    void benchmark_sm4_bs_ro_neon_ctr_encrypt(uint8_t *plain, uint8_t *cipher,int size,uint8_t rk[32][8][16],uint8_t * iv);
    void benchmark_sm4_bs_ro_neon_gcm_encrypt(uint8_t *plain, uint8_t *cipher,int size,uint8_t rk[32][8][16],
        uint8_t * iv, int iv_len, uint8_t *add ,int add_len,
        uint8_t *tag, int tag_len, uint8_t T[][256][16]);
#endif

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
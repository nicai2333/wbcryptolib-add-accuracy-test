/*
 * @Descripttion : bitslice register optimization sm4 with ecb, ctr and gcm mode
 * @Version      : 
 * @Autor        : ryanclq
 * @Date         : 2023-07-6 15:51:47
 * @LastEditTime : 2023-07-6 16:04:15
 * @FilePath     : /src/sm4_bs/sm4_bs_ro.c
 */
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "crypto/sm4_bs_ro.h"

static const unsigned char SboxTable[16][16] = 
{
    {0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05},
    {0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99},
    {0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62},
    {0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6},
    {0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8},
    {0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35},
    {0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87},
    {0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e},
    {0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1},
    {0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3},
    {0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f},
    {0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51},
    {0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8},
    {0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0},
    {0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84},
    {0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48}
};

static void big_endian_store32(uint8_t *x, uint32_t u)
{
    x[3] = u & 0xFF; u >>= 8;
    x[2] = u & 0xFF; u >>= 8;
    x[1] = u & 0xFF; u >>= 8;
    x[0] = u & 0xFF;
}

static void big_endian_store64(uint8_t *x, uint64_t u)
{
    x[7] = u & 0xFF; u >>= 8;
    x[6] = u & 0xFF; u >>= 8;
    x[5] = u & 0xFF; u >>= 8;
    x[4] = u & 0xFF; u >>= 8;
    x[3] = u & 0xFF; u >>= 8;
    x[2] = u & 0xFF; u >>= 8;
    x[1] = u & 0xFF; u >>= 8;
    x[0] = u & 0xFF;
}


/**
 * @brief Computes (a + x)*y.
 * 
 * @param a The input/output vector a, 16 bytes long
 * @param x The input vector x, x_len bytes long
 * @param x_len The length of vector x (in bytes)
 * @param y The input vector y, 16 bytes long
 */
static void add_mul(uint8_t *a,
                    const uint8_t *x, 
                    size_t x_len,
                    const uint8_t *y)
{
    int32_t i, j;
    uint8_t a_bits[128], y_bits[128];
    uint8_t axy_bits[256];
    
    for (i = 0; i < (int)x_len; ++i)
    {
        a[i] ^= x[i];
    }

    /* Performs reflection on (a + x) and y */
    for (i = 0; i < 128; ++i)
    {
        a_bits[i] = (a[i >> 3] >> (7 - (i & 7))) & 1;
        y_bits[i] = (y[i >> 3] >> (7 - (i & 7))) & 1;
    }

    crypto_memzero(axy_bits, sizeof(axy_bits));
    for (i = 0; i < 128; ++i)
    {
        for (j = 0; j < 128; ++j)
        {
            axy_bits[i + j] ^= a_bits[i] & y_bits[j];
        }
    }

    /**
     * Galois field reduction, GF(2^128) is defined 
     * by polynomial x^128 + x^7 + x^2 + 1
     */
    for (i = 127; i >= 0; --i)
    {
        axy_bits[i]       ^= axy_bits[i + 128];
        axy_bits[i +   1] ^= axy_bits[i + 128];
        axy_bits[i +   2] ^= axy_bits[i + 128];
        axy_bits[i +   7] ^= axy_bits[i + 128];
        axy_bits[i + 128] ^= axy_bits[i + 128];
    }

    /* Undo the reflection on the output */
    crypto_memzero(a, 16);
    for (i = 0; i < 128; ++i)
    {
        a[i >> 3] |= (axy_bits[i] << (7 - (i & 7)));
    }
}


/*
 * private function:
 * look up in SboxTable and get the related value.
 * args:    [in] inch: 0x00~0xFF (8 bits unsigned value).
 */
static unsigned char sm4Sbox(unsigned char inch)
{
    unsigned char *pTable = (unsigned char *)SboxTable;
    unsigned char retVal = (unsigned char)(pTable[inch]);
    return retVal;
}

/* private function:
 * Calculating round encryption key.
 * args:    [in] a: a is a 32 bits unsigned value;
 * return: sk[i]: i{0,1,2,3,...31}.
 */
static unsigned long sm4CalciRK(unsigned long ka)
{
    unsigned long bb = 0;
    unsigned long rk = 0;
    unsigned char a[4];
    unsigned char b[4];
    PUT_ULONG_BE(ka,a,0)
    b[0] = sm4Sbox(a[0]);
    b[1] = sm4Sbox(a[1]);
    b[2] = sm4Sbox(a[2]);
    b[3] = sm4Sbox(a[3]);
	GET_ULONG_BE(bb,b,0)
    rk = bb^(ROTL(bb, 13))^(ROTL(bb, 23));
    return rk;
}

static unsigned char test_key[] = {
        0x00,0x01,0x00,0x02,0x00,0x03,0x00,0x04,
        0x00,0x05,0x00,0x06,0x00,0x07,0x00,0x08,
};
static unsigned char test_aad[] = {
        0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x03,0x7f,0xff,0xff,0xfe,0x89,0x2c,0x38,0x00,
        0x00,0x5c,0x36,0x5c,0x36,0x5c,0x36
};
static unsigned char test_iv_enc[] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};


static unsigned char test_ecount_buf[16]={0x00};
static unsigned int test_num = 0;
static unsigned char test_input[16384]={0};
static unsigned char test_output[16384];
static unsigned char test_tag[16] = {0};

#define SWAP(a,b) { uint32_t t = a; a = b; b = t; t = 0; }

#if defined(WBCRYPTO_SM4_BS_RO_256)
    static void print_m256i(__m256i value) {
        // 将__m256i转换为一个32位整数数组
        uint32_t arr[8];
        _mm256_storeu_si256((__m256i*)arr, value);

        // 逐个打印32位整数的比特
        for (int i = 0; i < 8; i++) {
            for (int j = 31; j >= 0; j--) {
                uint64_t mask = 1ULL << j;
                printf("%d", (arr[i] & mask) ? 1 : 0);
                if(j%8 == 0) printf(" ");
            }
            printf(" "); // 可以根据需要添加分隔符
        }
        printf("\n");
    }

    __m256i loopShiftLeft(__m256i input, int n) {
        // 将输入数据循环左移n位
        __m256i shifted = _mm256_slli_epi32(input, n);

        uint maskNum = 0;
        uint addNum = 0x80000000;
        for (int i = 0; i < n; i++)
        {
            maskNum = maskNum + addNum ;
            addNum = addNum >> 1;
        }
        // 获取最高n位的值
        __m256i highestBit = _mm256_and_si256(input, _mm256_set1_epi32(maskNum));
        __m256i swap = _mm256_setr_epi32(1,2,3,4,5,6,7,0);
        highestBit = _mm256_permutevar8x32_epi32(highestBit,swap);//todo 这里是循环移位了,不循环可以用blend取old_shifted的最前面32bit和new_shifted的后224bit
        highestBit = _mm256_srli_epi32(highestBit,32-n);
        shifted = _mm256_or_si256(shifted,highestBit);
        return shifted;
    }
    __m256i loopShiftRight(__m256i input, int n) {
        // 将输入数据循环右移n位
        __m256i shifted = _mm256_srli_epi32(input, n);

        uint maskNum = 0;
        uint addNum = 1;
        for (int i = 0; i < n; i++)
        {
            maskNum = maskNum + addNum ;
            addNum = addNum << 1;
        }
        // 获取最低n位的值
        __m256i lowestBit = _mm256_and_si256(input, _mm256_set1_epi32(maskNum));
        __m256i swap = _mm256_setr_epi32(7,0,1,2,3,4,5,6);
        lowestBit = _mm256_permutevar8x32_epi32(lowestBit,swap);
        lowestBit = _mm256_slli_epi32(lowestBit,32-n);
        shifted = _mm256_or_si256(shifted,lowestBit);
        return shifted;
    }
    __m256i shiftLeft(__m256i input, int n) {
        // 将输入数据循环左移n位,n不大于32
        __m256i oldShifted = _mm256_slli_epi32(input, n);

        uint maskNum = 0;
        uint addNum = 0x80000000;
        for (int i = 0; i < n; i++)
        {
            maskNum = maskNum + addNum ;
            addNum = addNum >> 1;
        }
        // 获取最高n位的值
        __m256i highestBit = _mm256_and_si256(input, _mm256_set1_epi32(maskNum));
        __m256i swap = _mm256_setr_epi32(1,2,3,4,5,6,7,0);
        highestBit = _mm256_permutevar8x32_epi32(highestBit,swap);
        highestBit = _mm256_srli_epi32(highestBit,32-n);
        __m256i newShifted = _mm256_or_si256(oldShifted,highestBit);
        newShifted = _mm256_blend_epi32(oldShifted,newShifted,0b01111111);
        return newShifted;
    }
    __m256i shiftRight(__m256i input, int n) {
        // 将输入数据循环右移n位,n不大于32
        __m256i oldShifted = _mm256_srli_epi32(input, n);

        uint maskNum = 0;
        uint addNum = 1;
        for (int i = 0; i < n; i++)
        {
            maskNum = maskNum + addNum ;
            addNum = addNum << 1;
        }
        // 获取最低n位的值
        __m256i lowestBit = _mm256_and_si256(input, _mm256_set1_epi32(maskNum));
        __m256i swap = _mm256_setr_epi32(7,0,1,2,3,4,5,6);
        lowestBit = _mm256_permutevar8x32_epi32(lowestBit,swap);
        lowestBit = _mm256_slli_epi32(lowestBit,32-n);
        __m256i newShifted = _mm256_or_si256(oldShifted,lowestBit);
        newShifted = _mm256_blend_epi32(oldShifted,newShifted,0b11111110);
        return newShifted;
    }
    void sm4_bsro256_gcm_init(gcm_context *context, unsigned char *key,
    uint8_t BS_RK_256[32][8][32], unsigned char *iv)
    {
        //key_schedule
        sm4_bsro256_key_schedule(key,BS_RK_256);
        //compute table, init h and E(y0)

        uint8_t p_h[32],c_h[32];
        memset(p_h, 0, 32);//all 0
        memcpy(p_h+16, iv, 16);//iv||counter0
        memset(p_h+31, 1, 1);
        sm4_bsro256_ecb_encrypt(c_h,p_h,32,BS_RK_256);
        computeTable(context->T, c_h);
        memcpy(context->H, c_h, 16);
        memcpy(context->Enc_y0, c_h+16, 16);
    }

    void sm4_bsro256_gcm_encrypt(uint8_t *outputb, uint8_t *inputb, int size,
        uint8_t rk[32][8][32], uint8_t *iv, int iv_len, uint8_t *add ,int add_len,
        uint8_t *tag, int tag_len, gcm_context *ctx)
    {
        uint8_t ctr[1024] = {0};
        __m256i input_space[32];
        __m256i output_space[32];
        __m256i round_key[32][8];
        __m128i iv_copy;
        __m128i count = _mm_setzero_si128();
        uint8_t op[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
        __m128i cnt = _mm_loadu_si128((__m128i*)op);
        int length = size;
        iv_copy = _mm_load_si128((__m128i *)iv);
        uint8_t *out = outputb;

        for (size_t i = 0; i < 32; i++)
        {
            for (size_t j = 0; j < 8; j++)
            {
                round_key[i][j] = _mm256_loadu_si256((const __m256i *)rk[i][j]);
            }
        }

        for(int j = 0; size; ++j)
        {
            int chunk = MIN(size, 1024);
            int blocks = chunk / 16;

            count = _mm_add_epi64(count,cnt);
            
            for (int i = 0; i < blocks; i++)//gcm mode need more 1 block
            {
                //gcm mode iv from 0x02!
                count = _mm_add_epi64(count,cnt);
                _mm_storeu_si128((__m128i*)(ctr+i*16),iv_copy + count);
            }

            memset(input_space,0,1024);
            int num = chunk/32;
            if (blocks % 2 != 0)
                num++;
            
            for (size_t i = 0; i < num; i++)
            {
                input_space[i] = _mm256_loadu_si256((const __m256i *)ctr + i);
            }

            //bs_cipher(ctr, rk);
            sm4_bsro256_enc(input_space,output_space,round_key);

            uint8_t *outputp = (uint8_t*)output_space;
            memcpy(out,outputp,chunk);

            size -= chunk;
            out += chunk;

            for(int i = j*1024; i < chunk+j*1024; i++)
            {
                outputb[i] ^= inputb[i];
            }
        }
        
        //Auth tag test
        //compute tag
        ghash(ctx->T, add,add_len, outputb, length, ctx->buff);
        //uint8_t *ency1 = (uint8_t *) ctr + 16;
        for (int i = 0; i < tag_len; i++)
        {
            tag[i] = ctx->buff[i] ^ ctx->Enc_y0[i];
        }

        //gcm_free(context);

    }

    void sm4_bsro256_ctr_encrypt(uint8_t * outputb, uint8_t * inputb, int size, uint8_t rk [32][8][32], uint8_t * iv)
    {
        uint8_t ctr[1024] = {0};
        __m256i input_space[32];
        __m256i output_space[32];
        __m256i round_key[32][8];
        __m128i iv_copy;
        __m128i count = _mm_setzero_si128();
        uint8_t op[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
        __m128i cnt = _mm_loadu_si128((__m128i*)op);
        uint8_t *out = outputb;
    
        iv_copy = _mm_load_si128((__m128i *)iv);

        for (size_t i = 0; i < 32; i++)
        {
            for (size_t j = 0; j < 8; j++)
            {
                round_key[i][j] = _mm256_loadu_si256((const __m256i *)rk[i][j]);
            }
        }

        for(int j=0;size;j++)
        {
            int chunk = MIN(size, 1024);
            int blocks = chunk / 16;//分组数

            for (int i = 0; i < blocks; i++)
            {
                _mm_storeu_si128((__m128i*)(ctr+i*16),iv_copy + count);
                count = _mm_add_epi64(count,cnt);
            }

            memset(input_space,0,1024);
            int num = chunk/32;
            if (blocks % 2 != 0)
                num++;
            for (size_t i = 0; i < num; i++)
            {
                input_space[i] = _mm256_loadu_si256((const __m256i *)ctr + i);
            }
        
            sm4_bsro256_enc(input_space,output_space,round_key);

            uint8_t *outputp = (uint8_t*)output_space;
            memcpy(out,outputp,chunk);

            size -= chunk;
            out += chunk;

            for(int i = j*1024; i < chunk+j*1024; i++)
            {
                outputb[i] ^= inputb[i];
            }

        }
    }

    void sm4_bsro256_ecb_encrypt(uint8_t* outputb, uint8_t* inputb, int size, uint8_t rk [32][8][32])
    {
        __m256i output_space[32];
        __m256i input_space[32];
        __m256i round_key[32][8];
        memset(outputb,0,size);
        uint8_t* out = outputb;
        uint8_t* in = inputb;
        
        for (size_t i = 0; i < 32; i++)
        {
            for (size_t j = 0; j < 8; j++)
            {
                round_key[i][j] = _mm256_loadu_si256((const __m256i *)rk[i][j]);
            }
        }
        
        while(size > 0)
        {
            if(size < 1024)//64*128/8 输入明文字节数，正常的是256*128/8
            {
                memset(input_space,0,1024);
                int num = size / 32;
                if (size % 32 != 0)
                    num++;
                for (size_t i = 0; i < num; i++)
                {
                    input_space[i] = _mm256_loadu_si256((const __m256i *)in + i);
                }
                
                sm4_bsro256_enc(input_space,output_space,round_key);
            
                uint8_t *outputp = (uint8_t*)output_space;
                memcpy(out,outputp,size);

                size = 0;
            
            }
            else
            {
                memset(input_space,0,1024);

                for (size_t i = 0; i < 32; i++)
                {
                    input_space[i] = _mm256_loadu_si256((const __m256i *)in + i);
                }
    
                sm4_bsro256_enc(input_space,output_space,round_key);

                uint8_t *outputp = (uint8_t*)output_space;
                memcpy(out,outputp,1024);

                size -= 1024;
                out += 1024;
                in += 1024;
            }
            
        }
    }
    void sm4_bsro256_key_schedule(uint8_t* key, uint8_t BS_RK [32][8][32])//BS_RK_256 32个32*__m256i应该修改为32个8*__m256i
    {
        uint32_t rkey[32];
        // System parameter or family key
        const uint32_t FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };

        const uint32_t CK[32] = {
        0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
        0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
        0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
        0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
        0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
        0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
        0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
        0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
        };

        uint32_t K[36];
        uint32_t MK[4];
        GET_ULONG_BE( MK[0], key, 0 );
        GET_ULONG_BE( MK[1], key, 4 );
        GET_ULONG_BE( MK[2], key, 8 );
        GET_ULONG_BE( MK[3], key, 12 );

        K[0] = MK[0] ^ FK[0];
        K[1] = MK[1] ^ FK[1];
        K[2] = MK[2] ^ FK[2];
        K[3] = MK[3] ^ FK[3];

        for(int i = 0; i<32; i++)
        {
            K[i+4] = K[i] ^ (sm4CalciRK(K[i+1]^K[i+2]^K[i+3]^CK[i]));
            rkey[i] = K[i+4];
            //printf("rkey[%d]=%08x\n",i,rkey[i]);
        }
        //rkey[] 也可以用把32*64个一样的轮密钥放入8个ymm寄存器中然后再8*8转置，循环32组轮密钥来进行，比较容易理解，但是可能没现在这种直接赋值的快？？
        for(int i = 0; i < 32; i++)//rkey的循环
        { 
            uint32_t t = 0x80000000;
            for(int j = 0; j < 32; j++)//rkey[i]的位的循环
            {   
                int tmp = j/8;//j/8向下取整，因为同一256位的寄存器中，每32bit是一样的，所以同时放在0，4，8，12，16，20，24，28的uint8_t中的
                if(rkey[i] & t)
                {   
                    BS_RK[i][j%8][0+tmp] = ~0;
                    BS_RK[i][j%8][4+tmp] = ~0;
                    BS_RK[i][j%8][8+tmp] = ~0;
                    BS_RK[i][j%8][12+tmp] = ~0;
                    BS_RK[i][j%8][16+tmp] = ~0;
                    BS_RK[i][j%8][20+tmp] = ~0;
                    BS_RK[i][j%8][24+tmp] = ~0;
                    BS_RK[i][j%8][28+tmp] = ~0;
                    
                }
                else
                {
                    BS_RK[i][j%8][0+tmp] = 0;
                    BS_RK[i][j%8][4+tmp] = 0;
                    BS_RK[i][j%8][8+tmp] = 0;
                    BS_RK[i][j%8][12+tmp] = 0;
                    BS_RK[i][j%8][16+tmp] = 0;
                    BS_RK[i][j%8][20+tmp] = 0;
                    BS_RK[i][j%8][24+tmp] = 0;
                    BS_RK[i][j%8][28+tmp] = 0;
                }
                
                t = t >> 1;
            }
        }
    }



    static void BS_RO_iteration(__m256i IN[32], __m256i BS_RK_256[32][8])
    {
        uint64_t t1 , t2;
        __m256i tmp;
        __m256i ymm[8];
        //四轮放在一起执行，减少32位移位操作
        for (int i = 0; i < 32; i+=4)
        {
            for (int j = 0; j < 8; j++)//32位异或操作
            {
                ymm[j] = IN[8+j] ^ IN[16+j] ^ IN[24+j] ^ BS_RK_256[i][j];
                //print_m256i(rk);
            }
            
            S_box(ymm);//正确
        
            L_tran(ymm);

            for (int j = 0; j < 8; j++)//32位异或操作
            {
                IN[j] = _mm256_xor_si256(ymm[j],IN[j]);
            }

            for (int j = 0; j < 8; j++)//32位异或操作
            {
                ymm[j] = IN[j] ^ IN[16+j] ^ IN[24+j] ^ BS_RK_256[i+1][j];
                //print_m256i(rk);
            }
            
            S_box(ymm);//正确
        
            L_tran(ymm);
            
            for (int j = 0; j < 8; j++)//32位异或操作
            {
                IN[j+8] = _mm256_xor_si256(ymm[j],IN[j+8]);
            }

            for (int j = 0; j < 8; j++)//32位异或操作
            {
                ymm[j] = IN[j] ^ IN[8+j] ^ IN[24+j] ^ BS_RK_256[i+2][j];
                //print_m256i(rk);
            }
            
            S_box(ymm);//正确
        
            L_tran(ymm);
            
            for (int j = 0; j < 8; j++)//32位异或操作
            {
                IN[j+16] = _mm256_xor_si256(ymm[j],IN[j+16]);
            }

            for (int j = 0; j < 8; j++)//32位异或操作
            {
                ymm[j] = IN[j] ^ IN[8+j] ^ IN[16+j] ^ BS_RK_256[i+3][j];
                //print_m256i(rk);
            }
            
            S_box(ymm);//正确
        
            L_tran(ymm);
            
            for (int j = 0; j < 8; j++)//32位异或操作
            {
                IN[j+24] = _mm256_xor_si256(ymm[j],IN[j+24]);
            }

        }
    
        for (int j = 0; j < 8; j++)//反序变换
        {
            tmp = IN[j];
            IN[j] = IN[j+24];
            IN[j+24] = tmp;
            tmp = IN[j+8];
            IN[j+8] = IN[j+16];
            IN[j+16] = tmp;
        }

    }


    static void S_box(__m256i *buf_256)
    {
        bits sm4;

        
            sm4.b7 = buf_256[0];//todo 顺序不一定对
            sm4.b6 = buf_256[1];
            sm4.b5 = buf_256[2];
            sm4.b4 = buf_256[3];
            sm4.b3 = buf_256[4];
            sm4.b2 = buf_256[5];
            sm4.b1 = buf_256[6];
            sm4.b0 = buf_256[7];

            Sm4_BoolFun(sm4,&buf_256[7],&buf_256[6],&buf_256[5],&buf_256[4],
                &buf_256[3],&buf_256[2],&buf_256[1],&buf_256[0]);

        //for(int )

    }

    static void L_tran(__m256i *buf_256)
    {
        __m256i state[8];
        state[0] = buf_256[0]^buf_256[2]^L_shuffle(buf_256[2],8)^L_shuffle(buf_256[2],16)^L_shuffle(buf_256[0],24);
        state[1] = buf_256[1]^buf_256[3]^L_shuffle(buf_256[3],8)^L_shuffle(buf_256[3],16)^L_shuffle(buf_256[1],24);
        state[2] = buf_256[2]^buf_256[4]^L_shuffle(buf_256[4],8)^L_shuffle(buf_256[4],16)^L_shuffle(buf_256[2],24);
        state[3] = buf_256[3]^buf_256[5]^L_shuffle(buf_256[5],8)^L_shuffle(buf_256[5],16)^L_shuffle(buf_256[3],24); 
        state[4] = buf_256[4]^buf_256[6]^L_shuffle(buf_256[6],8)^L_shuffle(buf_256[6],16)^L_shuffle(buf_256[4],24);
        state[5] = buf_256[5]^buf_256[7]^L_shuffle(buf_256[7],8)^L_shuffle(buf_256[7],16)^L_shuffle(buf_256[5],24);
        state[6] = buf_256[6]^L_shuffle(buf_256[0],8)^L_shuffle(buf_256[0],16)^L_shuffle(buf_256[0],24)^L_shuffle(buf_256[6],24);//todo 正确性有待验证,shuffle是在128内循环的,可能可以用aln
        state[7] = buf_256[7]^L_shuffle(buf_256[1],8)^L_shuffle(buf_256[1],16)^L_shuffle(buf_256[1],24)^L_shuffle(buf_256[7],24);

        for (int i = 0; i < 8; i++)
        {
            buf_256[i] = state[i];
        }
    }

    static __m256i L_shuffle(__m256i data, int move)
    {
        __m256i swap;
        __m256i result;
        switch (move)
        {
        case 8:
            swap = _mm256_setr_epi8(1,2,3,0,5,6,7,4,9,10,11,8,13,14,15,12,1,2,3,0,5,6,7,4,9,10,11,8,13,14,15,12);
            result = _mm256_shuffle_epi8(data,swap);
            break;
        
        case 16:
            swap = _mm256_setr_epi8(2,3,0,1,6,7,4,5,10,11,8,9,14,15,12,13,2,3,0,1,6,7,4,5,10,11,8,9,14,15,12,13);
            result = _mm256_shuffle_epi8(data,swap);
            break;
        
        case 24:
            swap = _mm256_setr_epi8(3,0,1,2,7,4,5,6,11,8,9,10,15,12,13,14,3,0,1,2,7,4,5,6,11,8,9,10,15,12,13,14);
            result = _mm256_shuffle_epi8(data,swap);
            break;

        default:
            printf("\nvalues of move should be one of the numbers 8,16,24 \n");
            break;
        }
        return result;
    }

    void sm4_bsro256_enc(__m256i IN[32],__m256i OUT[32], __m256i rk [32][8])
    {
        __m256i state[32];
        BS_RO_PACK(IN,state);//数据打包
        // printf("\nafter-pack:\n");
        // dump_hex(state,1024);
        BS_RO_TRANS(state,IN);//数据转置
        // printf("\nafter-tran:\n");
        // dump_hex(IN,1024);
        BS_RO_iteration(IN,rk);
        // printf("\nafter-sbox:\n");
        // dump_hex(IN,1024);
        BS_RO_TRANS(IN,state);//数据逆转置
        // printf("\nstate:\n");
        // dump_hex(state,1024);
        BS_RO_UNPACK(state,OUT);//数据逆打包
        // printf("\nout:\n");
        // dump_hex(OUT,1024);
    }

    void BS_RO_PACK(__m256i IN[32], __m256i OUT[32])
    { 
        __m256i state[16];
        //lo32再lo64取出a1,lo32再hi64取出a2,hi32再lo64取出a3,hi32再hi64取出a4
        state[0] = _mm256_unpacklo_epi32(IN[0],IN[1]);//lo32
        state[1] = _mm256_unpacklo_epi32(IN[2],IN[3]);
        state[2] = _mm256_unpacklo_epi32(IN[4],IN[5]);
        state[3] = _mm256_unpacklo_epi32(IN[6],IN[7]);
        state[4] = _mm256_unpacklo_epi32(IN[8],IN[9]);
        state[5] = _mm256_unpacklo_epi32(IN[10],IN[11]);
        state[6] = _mm256_unpacklo_epi32(IN[12],IN[13]);
        state[7] = _mm256_unpacklo_epi32(IN[14],IN[15]);
        state[8] = _mm256_unpacklo_epi32(IN[16],IN[17]);
        state[9] = _mm256_unpacklo_epi32(IN[18],IN[19]);
        state[10] = _mm256_unpacklo_epi32(IN[20],IN[21]);
        state[11] = _mm256_unpacklo_epi32(IN[22],IN[23]);
        state[12] = _mm256_unpacklo_epi32(IN[24],IN[25]);
        state[13] = _mm256_unpacklo_epi32(IN[26],IN[27]);
        state[14] = _mm256_unpacklo_epi32(IN[28],IN[29]);
        state[15] = _mm256_unpacklo_epi32(IN[30],IN[31]);

        OUT[0] = _mm256_unpacklo_epi64(state[0],state[1]);//lo32再lo64取出a1
        OUT[1] = _mm256_unpacklo_epi64(state[2],state[3]);
        OUT[2] = _mm256_unpacklo_epi64(state[4],state[5]);
        OUT[3] = _mm256_unpacklo_epi64(state[6],state[7]);
        OUT[4] = _mm256_unpacklo_epi64(state[8],state[9]);
        OUT[5] = _mm256_unpacklo_epi64(state[10],state[11]);
        OUT[6] = _mm256_unpacklo_epi64(state[12],state[13]);
        OUT[7] = _mm256_unpacklo_epi64(state[14],state[15]);

        OUT[8] = _mm256_unpackhi_epi64(state[0],state[1]);//lo32再hi64取出a2
        OUT[9] = _mm256_unpackhi_epi64(state[2],state[3]);
        OUT[10] = _mm256_unpackhi_epi64(state[4],state[5]);
        OUT[11] = _mm256_unpackhi_epi64(state[6],state[7]);
        OUT[12] = _mm256_unpackhi_epi64(state[8],state[9]);
        OUT[13] = _mm256_unpackhi_epi64(state[10],state[11]);
        OUT[14] = _mm256_unpackhi_epi64(state[12],state[13]);
        OUT[15] = _mm256_unpackhi_epi64(state[14],state[15]);
        
        state[0] = _mm256_unpackhi_epi32(IN[0],IN[1]);//hi32
        state[1] = _mm256_unpackhi_epi32(IN[2],IN[3]);
        state[2] = _mm256_unpackhi_epi32(IN[4],IN[5]);
        state[3] = _mm256_unpackhi_epi32(IN[6],IN[7]);
        state[4] = _mm256_unpackhi_epi32(IN[8],IN[9]);
        state[5] = _mm256_unpackhi_epi32(IN[10],IN[11]);
        state[6] = _mm256_unpackhi_epi32(IN[12],IN[13]);
        state[7] = _mm256_unpackhi_epi32(IN[14],IN[15]);
        state[8] = _mm256_unpackhi_epi32(IN[16],IN[17]);
        state[9] = _mm256_unpackhi_epi32(IN[18],IN[19]);
        state[10] = _mm256_unpackhi_epi32(IN[20],IN[21]);
        state[11] = _mm256_unpackhi_epi32(IN[22],IN[23]);
        state[12] = _mm256_unpackhi_epi32(IN[24],IN[25]);
        state[13] = _mm256_unpackhi_epi32(IN[26],IN[27]);
        state[14] = _mm256_unpackhi_epi32(IN[28],IN[29]);
        state[15] = _mm256_unpackhi_epi32(IN[30],IN[31]);
        
        OUT[16] = _mm256_unpacklo_epi64(state[0],state[1]);//hi32再lo64取出a3
        OUT[17] = _mm256_unpacklo_epi64(state[2],state[3]);
        OUT[18] = _mm256_unpacklo_epi64(state[4],state[5]);
        OUT[19] = _mm256_unpacklo_epi64(state[6],state[7]);
        OUT[20] = _mm256_unpacklo_epi64(state[8],state[9]);
        OUT[21] = _mm256_unpacklo_epi64(state[10],state[11]);
        OUT[22] = _mm256_unpacklo_epi64(state[12],state[13]);
        OUT[23] = _mm256_unpacklo_epi64(state[14],state[15]);

        OUT[24] = _mm256_unpackhi_epi64(state[0],state[1]);//hi32再hi64取出a4
        OUT[25] = _mm256_unpackhi_epi64(state[2],state[3]);
        OUT[26] = _mm256_unpackhi_epi64(state[4],state[5]);
        OUT[27] = _mm256_unpackhi_epi64(state[6],state[7]);
        OUT[28] = _mm256_unpackhi_epi64(state[8],state[9]);
        OUT[29] = _mm256_unpackhi_epi64(state[10],state[11]);
        OUT[30] = _mm256_unpackhi_epi64(state[12],state[13]);
        OUT[31] = _mm256_unpackhi_epi64(state[14],state[15]);
    
    }

    void BS_RO_UNPACK(__m256i IN[32], __m256i OUT[32])
    { 
        __m256i state1[8];
        __m256i state2[8];
        //对传入的第一组和第二组（原128bit的第一组32bit和第二组32bit）进行lo32
        state1[0] = _mm256_unpacklo_epi32(IN[0],IN[8]);
        state1[1] = _mm256_unpacklo_epi32(IN[1],IN[9]);
        state1[2] = _mm256_unpacklo_epi32(IN[2],IN[10]);
        state1[3] = _mm256_unpacklo_epi32(IN[3],IN[11]);
        state1[4] = _mm256_unpacklo_epi32(IN[4],IN[12]);
        state1[5] = _mm256_unpacklo_epi32(IN[5],IN[13]);
        state1[6] = _mm256_unpacklo_epi32(IN[6],IN[14]);
        state1[7] = _mm256_unpacklo_epi32(IN[7],IN[15]);

        //第三组和第四组进行lo32
        state2[0] = _mm256_unpacklo_epi32(IN[16],IN[24]);
        state2[1] = _mm256_unpacklo_epi32(IN[17],IN[25]);
        state2[2] = _mm256_unpacklo_epi32(IN[18],IN[26]);
        state2[3] = _mm256_unpacklo_epi32(IN[19],IN[27]);
        state2[4] = _mm256_unpacklo_epi32(IN[20],IN[28]);
        state2[5] = _mm256_unpacklo_epi32(IN[21],IN[29]);
        state2[6] = _mm256_unpacklo_epi32(IN[22],IN[30]);
        state2[7] = _mm256_unpacklo_epi32(IN[23],IN[31]);

        //对state1和state2中的结果进行lo64取出a、b、i、j......注意OUT的下标，ab是0，cd是1，ef是2，gh是3，ij是4.......
        OUT[0] = _mm256_unpacklo_epi64(state1[0],state2[0]);
        OUT[4] = _mm256_unpacklo_epi64(state1[1],state2[1]);
        OUT[8] = _mm256_unpacklo_epi64(state1[2],state2[2]);
        OUT[12] = _mm256_unpacklo_epi64(state1[3],state2[3]);
        OUT[16] = _mm256_unpacklo_epi64(state1[4],state2[4]);
        OUT[20] = _mm256_unpacklo_epi64(state1[5],state2[5]);
        OUT[24] = _mm256_unpacklo_epi64(state1[6],state2[6]);
        OUT[28] = _mm256_unpacklo_epi64(state1[7],state2[7]);

        //对state1和state2中的结果进行hi64取出c、d、k、l......
        OUT[1] = _mm256_unpackhi_epi64(state1[0],state2[0]);
        OUT[5] = _mm256_unpackhi_epi64(state1[1],state2[1]);
        OUT[9] = _mm256_unpackhi_epi64(state1[2],state2[2]);
        OUT[13] = _mm256_unpackhi_epi64(state1[3],state2[3]);
        OUT[17] = _mm256_unpackhi_epi64(state1[4],state2[4]);
        OUT[21] = _mm256_unpackhi_epi64(state1[5],state2[5]);
        OUT[25] = _mm256_unpackhi_epi64(state1[6],state2[6]);
        OUT[29] = _mm256_unpackhi_epi64(state1[7],state2[7]);
        
        //对传入的第一组和第二组进行hi32
        state1[0] = _mm256_unpackhi_epi32(IN[0],IN[8]);
        state1[1] = _mm256_unpackhi_epi32(IN[1],IN[9]);
        state1[2] = _mm256_unpackhi_epi32(IN[2],IN[10]);
        state1[3] = _mm256_unpackhi_epi32(IN[3],IN[11]);
        state1[4] = _mm256_unpackhi_epi32(IN[4],IN[12]);
        state1[5] = _mm256_unpackhi_epi32(IN[5],IN[13]);
        state1[6] = _mm256_unpackhi_epi32(IN[6],IN[14]);
        state1[7] = _mm256_unpackhi_epi32(IN[7],IN[15]);

        //对传入的第三组和第四组进行hi3
        state2[0] = _mm256_unpackhi_epi32(IN[16],IN[24]);
        state2[1] = _mm256_unpackhi_epi32(IN[17],IN[25]);
        state2[2] = _mm256_unpackhi_epi32(IN[18],IN[26]);
        state2[3] = _mm256_unpackhi_epi32(IN[19],IN[27]);
        state2[4] = _mm256_unpackhi_epi32(IN[20],IN[28]);
        state2[5] = _mm256_unpackhi_epi32(IN[21],IN[29]);
        state2[6] = _mm256_unpackhi_epi32(IN[22],IN[30]);
        state2[7] = _mm256_unpackhi_epi32(IN[23],IN[31]);
        
        //对state1和state2中的结果进行lo64取出e、f、m、n......
        OUT[2] = _mm256_unpacklo_epi64(state1[0],state2[0]);
        OUT[6] = _mm256_unpacklo_epi64(state1[1],state2[1]);
        OUT[10] = _mm256_unpacklo_epi64(state1[2],state2[2]);
        OUT[14] = _mm256_unpacklo_epi64(state1[3],state2[3]);
        OUT[18] = _mm256_unpacklo_epi64(state1[4],state2[4]);
        OUT[22] = _mm256_unpacklo_epi64(state1[5],state2[5]);
        OUT[26] = _mm256_unpacklo_epi64(state1[6],state2[6]);
        OUT[30] = _mm256_unpacklo_epi64(state1[7],state2[7]);

        //对state1和state2中的结果进行hi64取出g、h、o、p......
        OUT[3] = _mm256_unpackhi_epi64(state1[0],state2[0]);
        OUT[7] = _mm256_unpackhi_epi64(state1[1],state2[1]);
        OUT[11] = _mm256_unpackhi_epi64(state1[2],state2[2]);
        OUT[15] = _mm256_unpackhi_epi64(state1[3],state2[3]);
        OUT[19] = _mm256_unpackhi_epi64(state1[4],state2[4]);
        OUT[23] = _mm256_unpackhi_epi64(state1[5],state2[5]);
        OUT[27] = _mm256_unpackhi_epi64(state1[6],state2[6]);
        OUT[31] = _mm256_unpackhi_epi64(state1[7],state2[7]);
    }

    void BS_RO_TRANS(__m256i IN[32], __m256i OUT[32])
    {   
        __m256i temp, M;
        uint8_t k = 0;
        uint8_t r = 0;
        uint64_t m[3][4]={
            {0x5555555555555555,0x5555555555555555,0x5555555555555555,0x5555555555555555},
            {0x3333333333333333,0x3333333333333333,0x3333333333333333,0x3333333333333333},
            {0x0f0f0f0f0f0f0f0f,0x0f0f0f0f0f0f0f0f,0x0f0f0f0f0f0f0f0f,0x0f0f0f0f0f0f0f0f}
        };//0x55 = 01010101 0x33 = 00110011 0x0f = 00001111

        for (int round = 0; round < 4; round++)//每轮处理8*256个，一共传入32*256bit的数据
        {   
            for (int j = 0; j < 3; j++)
            {
                k = 1 << j;
                for (int i = 0; i < 8; i++)
                {
                    r = ((i - i % k) << 1) + (i % k);
                    if (r + k > 7) break;
                    M = _mm256_loadu_si256((__m256i*)m[j]);
                    temp = (IN[round * 8 + r] & shiftLeft(M,k)) ^ shiftRight((IN[round * 8 + r + k] & shiftLeft(M,k)),k);       
                    IN[round * 8 + r + k] = shiftLeft((IN[round * 8 + r] & M),k) ^ (IN[round * 8 + r + k] & M);
                    IN[round * 8 + r] = temp;
                }
            }
            for (int i = 0; i < 8; i++)
            {
                _mm256_storeu_si256(OUT + (round * 8 + i), IN[round * 8 + i]);
            }
        }
    }

    //130 gates - lwaes_isa
    static void Sm4_BoolFun(bits in, bit_t *out0, bit_t *out1, bit_t *out2, bit_t *out3, bit_t *out4, bit_t *out5, bit_t *out6, bit_t *out7){
            bit_t y_t[21], t_t[8], t_m[46], y_m[18], t_b[30];
            y_t[18] = in.b2 ^in.b6;
            t_t[ 0] = in.b3 ^in.b4;
            t_t[ 1] = in.b2 ^in.b7;
            t_t[ 2] = in.b7 ^y_t[18];
            t_t[ 3] = in.b1 ^t_t[ 1];
            t_t[ 4] = in.b6 ^in.b7;
            t_t[ 5] = in.b0 ^y_t[18];
            t_t[ 6] = in.b3 ^in.b6;
            y_t[10] = in.b1 ^y_t[18];
            y_t[ 0] = in.b5 ^~ y_t[10];
            y_t[ 1] = t_t[ 0] ^t_t[ 3];
            y_t[ 2] = in.b0 ^t_t[ 0];
            y_t[ 4] = in.b0 ^t_t[ 3];
            y_t[ 3] = in.b3 ^y_t[ 4];
            y_t[ 5] = in.b5 ^t_t[ 5];
            y_t[ 6] = in.b0 ^~ in.b1;
            y_t[ 7] = t_t[ 0] ^~ y_t[10];
            y_t[ 8] = t_t[ 0] ^t_t[ 5];
            y_t[ 9] = in.b3;
            y_t[11] = t_t[ 0] ^t_t[ 4];
            y_t[12] = in.b5 ^t_t[ 4];
            y_t[13] = in.b5 ^~ y_t[ 1];
            y_t[14] = in.b4 ^~ t_t[ 2];
            y_t[15] = in.b1 ^~ t_t[ 6];
            y_t[16] = in.b0 ^~ t_t[ 2];
            y_t[17] = t_t[ 0] ^~ t_t[ 2];
            y_t[19] = in.b5 ^~ y_t[14];
            y_t[20] = in.b0 ^t_t[ 1];

        //The shared non-linear middle part for AES, AES^-1, and SM4
            t_m[ 0] = y_t[ 3] ^	 y_t[12];
            t_m[ 1] = y_t[ 9] &	 y_t[ 5];
            t_m[ 2] = y_t[17] &	 y_t[ 6];
            t_m[ 3] = y_t[10] ^	 t_m[ 1];
            t_m[ 4] = y_t[14] &	 y_t[ 0];
            t_m[ 5] = t_m[ 4] ^	 t_m[ 1];
            t_m[ 6] = y_t[ 3] &	 y_t[12];
            t_m[ 7] = y_t[16] &	 y_t[ 7];
            t_m[ 8] = t_m[ 0] ^	 t_m[ 6];
            t_m[ 9] = y_t[15] &	 y_t[13];
            t_m[10] = t_m[ 9] ^	 t_m[ 6];
            t_m[11] = y_t[ 1] &	 y_t[11];
            t_m[12] = y_t[ 4] &	 y_t[20];
            t_m[13] = t_m[12] ^	 t_m[11];
            t_m[14] = y_t[ 2] &	 y_t[ 8];
            t_m[15] = t_m[14] ^	 t_m[11];
            t_m[16] = t_m[ 3] ^	 t_m[ 2];
            t_m[17] = t_m[ 5] ^	 y_t[18];
            t_m[18] = t_m[ 8] ^	 t_m[ 7];
            t_m[19] = t_m[10] ^	 t_m[15];
            t_m[20] = t_m[16] ^	 t_m[13];
            t_m[21] = t_m[17] ^	 t_m[15];
            t_m[22] = t_m[18] ^	 t_m[13];
            t_m[23] = t_m[19] ^	 y_t[19];
            t_m[24] = t_m[22] ^	 t_m[23];
            t_m[25] = t_m[22] &	 t_m[20];
            t_m[26] = t_m[21] ^	 t_m[25];
            t_m[27] = t_m[20] ^	 t_m[21];
            t_m[28] = t_m[23] ^	 t_m[25];
            t_m[29] = t_m[28] &	 t_m[27];
            t_m[30] = t_m[26] &	 t_m[24];
            t_m[31] = t_m[20] &	 t_m[23];
            t_m[32] = t_m[27] &	 t_m[31];
            t_m[33] = t_m[27] ^	 t_m[25];
            t_m[34] = t_m[21] &	 t_m[22];
            t_m[35] = t_m[24] &	 t_m[34];
            t_m[36] = t_m[24] ^	 t_m[25];
            t_m[37] = t_m[21] ^	 t_m[29];
            t_m[38] = t_m[32] ^	 t_m[33];
            t_m[39] = t_m[23] ^	 t_m[30];
            t_m[40] = t_m[35] ^	 t_m[36];
            t_m[41] = t_m[38] ^	 t_m[40];
            t_m[42] = t_m[37] ^	 t_m[39];
            t_m[43] = t_m[37] ^	 t_m[38];
            t_m[44] = t_m[39] ^	 t_m[40];
            t_m[45] = t_m[42] ^	 t_m[41];
            y_m[ 0] = t_m[38] &	 y_t[ 7];
            y_m[ 1] = t_m[37] &	 y_t[13];
            y_m[ 2] = t_m[42] &	 y_t[11];
            y_m[ 3] = t_m[45] &	 y_t[20];
            y_m[ 4] = t_m[41] &	 y_t[ 8];
            y_m[ 5] = t_m[44] &	 y_t[ 9];
            y_m[ 6] = t_m[40] &	 y_t[17];
            y_m[ 7] = t_m[39] &	 y_t[14];
            y_m[ 8] = t_m[43] &	 y_t[ 3];
            y_m[ 9] = t_m[38] &	 y_t[16];
            y_m[10] = t_m[37] &	 y_t[15];
            y_m[11] = t_m[42] &	 y_t[ 1];
            y_m[12] = t_m[45] &	 y_t[ 4];
            y_m[13] = t_m[41] &	 y_t[ 2];
            y_m[14] = t_m[44] &	 y_t[ 5];
            y_m[15] = t_m[40] &	 y_t[ 6];
            y_m[16] = t_m[39] &	 y_t[ 0];
            y_m[17] = t_m[43] &	 y_t[12];

        //bottom(outer) linear layer for sm4
            t_b[ 0] = y_m[ 4] ^	 y_m[ 7];
            t_b[ 1] = y_m[13] ^	 y_m[15];
            t_b[ 2] = y_m[ 2] ^	 y_m[16];
            t_b[ 3] = y_m[ 6] ^	 t_b[ 0];
            t_b[ 4] = y_m[12] ^	 t_b[ 1];
            t_b[ 5] = y_m[ 9] ^	 y_m[10];
            t_b[ 6] = y_m[11] ^	 t_b[ 2];
            t_b[ 7] = y_m[ 1] ^	 t_b[ 4];
            t_b[ 8] = y_m[ 0] ^	 y_m[17];
            t_b[ 9] = y_m[ 3] ^	 y_m[17];
            t_b[10] = y_m[ 8] ^	 t_b[ 3];
            t_b[11] = t_b[ 2] ^	 t_b[ 5];
            t_b[12] = y_m[14] ^	 t_b[ 6];
            t_b[13] = t_b[ 7] ^	 t_b[ 9];
            t_b[14] = y_m[ 0] ^	 y_m[ 6];
            t_b[15] = y_m[ 7] ^	 y_m[16];
            t_b[16] = y_m[ 5] ^	 y_m[13];
            t_b[17] = y_m[ 3] ^	 y_m[15];
            t_b[18] = y_m[10] ^	 y_m[12];
            t_b[19] = y_m[ 9] ^	 t_b[ 1];
            t_b[20] = y_m[ 4] ^	 t_b[ 4];
            t_b[21] = y_m[14] ^	 t_b[ 3];
            t_b[22] = y_m[16] ^	 t_b[ 5];
            t_b[23] = t_b[ 7] ^	 t_b[14];
            t_b[24] = t_b[ 8] ^	 t_b[11];
            t_b[25] = t_b[ 0] ^	 t_b[12];
            t_b[26] = t_b[17] ^	 t_b[ 3];
            t_b[27] = t_b[18] ^	 t_b[10];
            t_b[28] = t_b[19] ^	 t_b[ 6];
            t_b[29] = t_b[ 8] ^	 t_b[10];
            *out0 = t_b[11] ^~ t_b[13];
            *out1 = t_b[15] ^~ t_b[23];
            *out2 = t_b[20] ^	 t_b[24];
            *out3 = t_b[16] ^	 t_b[25];
            *out4 = t_b[26] ^~ t_b[22];
            *out5 = t_b[21] ^	 t_b[13];
            *out6 = t_b[27] ^~ t_b[12];
            *out7 = t_b[28] ^~ t_b[29];
    }

    void sm4_bsro256_ecb(uint8_t *output, uint8_t *input, int size, uint8_t *key_vector){
        uint8_t rk [32][8][32] = {0};
        sm4_bsro256_key_schedule(key_vector,rk);
        sm4_bsro256_ecb_encrypt(output,input,size,rk);
    }

    void sm4_bsro256_ctr(uint8_t *output, uint8_t *input, int size, uint8_t *key_vector, uint8_t *iv){
        
        uint8_t rk [32][8][32] = {0};
        sm4_bsro256_key_schedule(key_vector,rk); 
        //encrypt
        sm4_bsro256_ctr_encrypt(output, input, size, rk, iv);
        // printf("ciphertext: \n");
        // dump_hex(output,SM4_CTR_TESTS_BYTES);
    }

    void sm4_bsro256_gcm(uint8_t *output, uint8_t *input, int size, uint8_t *key_vector, int key_len, uint8_t *iv, int iv_len, uint8_t *tag, int tag_len, uint8_t *Associated_Data, int add_len){
        uint8_t rk [32][8][32] = {0};
        gcm_context *ctx = gcm_init();
        sm4_bsro256_gcm_init(ctx,key_vector,rk,iv);

        sm4_bsro256_gcm_encrypt(output,input,size,rk,
            iv,iv_len,Associated_Data, add_len,
            tag, tag_len,ctx);

        gcm_free(ctx);    // printf("\n");
    }

    void benchmark_sm4_bs_ro_256_ecb_encrypt(uint8_t *plain, uint8_t *cipher,int size,uint8_t rk[32][8][32])
    {
        int turns = 10000;
        clock_t t = clock();
        for(int i=0; i<turns; i++)
        {
            sm4_bsro256_ecb_encrypt(cipher,plain,size,rk);
        }
        clock_t t1 = clock();
        double tt = (double)(t1 - t) / (CLOCKS_PER_SEC*turns);
        double speed = (double) size / (1024 * 1024 * tt);
        // dump_hex(cipher,size);
        printf("BSRO256SM4_encrypt>>> blocks: %d, time: %f s, speed: %f Mb/s\n", size/16, tt, speed*8);
    }

    void benchmark_sm4_bs_ro_256_ctr_encrypt(uint8_t *plain, uint8_t *cipher,int size,uint8_t rk[32][8][32],uint8_t * iv)
    {
        int turns = 10000;
        clock_t t = clock();
        for(int i=0; i<turns; i++)
        {
            sm4_bsro256_ctr_encrypt(cipher,plain,size,rk,iv);
        }
        clock_t t1 = clock();
        double tt = (double)(t1 - t) / (CLOCKS_PER_SEC*turns);
        double speed = (double) size / (1024 * 1024 * tt);
        // dump_hex(cipher,size);
        printf("BSRO256SM4_encrypt>>> blocks: %d, time: %f s, speed: %f Mb/s\n", size/16, tt, speed*8);
    }
    void benchmark_sm4_bs_ro_256_gcm_encrypt(uint8_t *plain, uint8_t *cipher,int size,uint8_t rk[32][8][32],
        uint8_t * iv, int iv_len, uint8_t *add ,int add_len,
        uint8_t *tag, int tag_len, uint8_t T[][256][16])
    {
        int turns = 10000;
        clock_t t = clock();
        for(int i=0; i<turns; i++)
        {
            sm4_bsro256_gcm_encrypt(cipher,plain,size,rk,iv,iv_len,add,add_len,
                tag,tag_len,T);
        }
        double tt = (double)(clock() - t) / (CLOCKS_PER_SEC*turns);
        double speed = (double) size / (1024 * 1024 * tt);
        // dump_hex(cipher,size);
        printf("BSRO256SM4_encrypt>>> blocks: %d, time: %f s, speed: %f Mb/s\n", size/16, tt, speed*8);
    }
    size_t test_sm4_bsro256_gcm_crypt_loop(size_t size){

        size_t count = 0;
        uint8_t rk[32][8][32] = {0};
        gcm_context *ctx = gcm_init();
        sm4_bsro256_gcm_init(ctx,test_key,rk,test_iv_enc);
        for (count = 0; run && count < 0xffffffffffffffff; count++)
        {
            sm4_bsro256_gcm_encrypt(test_output, test_input, size, rk, test_iv_enc, 16, test_aad, 23, test_tag, 16, test_output);
        }
        return count;
    }

    size_t test_sm4_bsro256_ctr_crypt_loop(size_t size){
        size_t count = 0;
        uint8_t rk[32][8][32] = {0};
        sm4_bsro256_key_schedule(test_key,rk);
        for (count = 0; run && count < 0xffffffffffffffff; count++)
        {
            sm4_bsro256_ctr_encrypt(test_output, test_input, size, rk, test_iv_enc);
        }
        
        return count;
    }

    size_t test_sm4_bsro256_ecb_crypt_loop(size_t size){
        size_t count = 0;
        uint8_t rk[32][8][32] = {0};
        sm4_bsro256_key_schedule(test_key,rk);
        for (count = 0; run && count < 0xffffffffffffffff; count++)
        {
            sm4_bsro256_ecb_encrypt(test_output, test_input, size, rk);
        }
        
        return count;
    }


    void performance_test_sm4_bsro256()
    {
        size_t size[6] = {16, 64, 256, 1024, 8192, 16384};
        printf("\nsm4_bsro256_ecb:\n");
        performance_test_enc(test_sm4_bsro256_ecb_crypt_loop, size, 6, 3);
        printf("\nsm4_bsro256_ctr:\n");
        performance_test_enc(test_sm4_bsro256_ctr_crypt_loop, size, 6, 3);
        printf("\nsm4_bsro256_gcm:\n");
        performance_test_enc(test_sm4_bsro256_gcm_crypt_loop, size, 6, 3);
    }
#endif







#if defined(WBCRYPTO_SM4_BS_RO_512)

    void sm4_bsro512_ecb_encrypt(uint8_t* outputb, uint8_t* inputb, int size, uint8_t rk[32][8][64]){
        __m512i output_space[32];
        __m512i input_space[32];
        __m512i round_key[32][8];
        memset(outputb,0,size);
        uint8_t* out = outputb;
        uint8_t* in = inputb;

        for (size_t i = 0; i < 32; i++)
        {
            for (size_t j = 0; j < 8; j++)
            {
                round_key[i][j] = _mm512_loadu_si512((const __m512i *)rk[i][j]);
            }
        }
        
        while(size > 0)
        {
            if(size < 2048)
            {
                memset(input_space,0,2048);
                int num = size / 64;
                if (size % 64 != 0)
                    num++;
                for (size_t i = 0; i < num; i++)
                {
                    input_space[i] = _mm512_loadu_si512((const __m512i *)in + i);
                }
                
                sm4_bsro512_enc(input_space,output_space,round_key);
            
                uint8_t *outputp = (uint8_t*)output_space;
                memcpy(out,outputp,size);

                size = 0;
            
            }
            else
            {
                memset(input_space,0,2048);

                for (size_t i = 0; i < 32; i++)
                {
                    input_space[i] = _mm512_loadu_si512((const __m512i *)in + i);
                }
                
                sm4_bsro512_enc(input_space,output_space,round_key);

                uint8_t *outputp = (uint8_t*)output_space;
                memcpy(out,outputp,2048);

                size -= 2048;
                out += 2048;
                in += 2048;
            }
            
        }
    }

    void sm4_bsro512_ctr_encrypt(uint8_t * outputb, uint8_t * inputb, int size, uint8_t rk[32][8][64], uint8_t * iv)
    {
        uint8_t ctr[2048] = {0};
        __m512i input_space[32];
        __m512i output_space[32];
        __m512i round_key[32][8];
        __m128i iv_copy;
        __m128i count = _mm_setzero_si128();
        uint8_t op[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
        __m128i cnt = _mm_loadu_si128((__m128i*)op);
        uint8_t *out = outputb;
    
        iv_copy = _mm_load_si128((__m128i *)iv);

        for (size_t i = 0; i < 32; i++)
        {
            for (size_t j = 0; j < 8; j++)
            {
                round_key[i][j] = _mm512_loadu_si512((const __m512i *)rk[i][j]);
            }
        }

        for(int j=0;size;j++)
        {
            int chunk = MIN(size, 2048);
            int blocks = chunk / 16;//分组数

            for (int i = 0; i < blocks; i++)
            {
                _mm_storeu_si128((__m128i*)(ctr+i*16),iv_copy + count);
                count = _mm_add_epi64(count,cnt);
            }

            memset(input_space,0,2048);
            int num = chunk/64;
            if (blocks % 4 != 0)
                num++;
            for (size_t i = 0; i < num; i++)
            {
                input_space[i] = _mm512_loadu_si512((const __m512i *)ctr + i);
            }
        
            sm4_bsro512_enc(input_space,output_space,round_key);

            uint8_t *outputp = (uint8_t*)output_space;
            memcpy(out,outputp,chunk);

            size -= chunk;
            out += chunk;

            for(int i = j*2048; i < chunk+j*2048; i++)
            {
                outputb[i] ^= inputb[i];
            }

        }
    }

    void sm4_bsro512_gcm_encrypt(uint8_t *outputb, uint8_t *inputb, int size,
        uint8_t rk[32][8][64], uint8_t *iv, int iv_len, uint8_t *add ,int add_len,
        uint8_t *tag, int tag_len, gcm_context *ctx)
    {
        uint8_t ctr[2048] = {0};
        __m512i input_space[32];
        __m512i output_space[32];
        __m512i round_key[32][8];
        __m128i iv_copy;
        __m128i count = _mm_setzero_si128();
        uint8_t op[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
        __m128i cnt = _mm_loadu_si128((__m128i*)op);
        int length = size;
        iv_copy = _mm_load_si128((__m128i *)iv);
        uint8_t *out = outputb;

        for (size_t i = 0; i < 32; i++)
        {
            for (size_t j = 0; j < 8; j++)
            {
                round_key[i][j] = _mm512_loadu_si512((const __m512i *)rk[i][j]);
            }
        }

        for(int j = 0; size; ++j)
        {
            int chunk = MIN(size, 2048);
            int blocks = chunk / 16;

            count = _mm_add_epi64(count,cnt);
            
            for (int i = 0; i < blocks; i++)//gcm mode need more 1 block
            {
                //gcm mode iv from 0x02!
                count = _mm_add_epi64(count,cnt);
                _mm_storeu_si128((__m128i*)(ctr+i*16),iv_copy + count);
            }

            memset(input_space,0,2048);
            int num = chunk/64;
            if (blocks % 4 != 0)
                num++;
            
            for (size_t i = 0; i < num; i++)
            {
                input_space[i] = _mm512_loadu_si512((const __m512i *)ctr + i);
            }

            //bs_cipher(ctr, rk);
            sm4_bsro512_enc(input_space,output_space,round_key);

            uint8_t *outputp = (uint8_t*)output_space;
            memcpy(out,outputp,chunk);

            size -= chunk;
            out += chunk;

            for(int i = j*2048; i < chunk+j*2048; i++)
            {
                outputb[i] ^= inputb[i];
            }
        }
        
        //Auth tag test
        //compute tag
        ghash(ctx->T, add,add_len, outputb, length, ctx->buff);
        //uint8_t *ency1 = (uint8_t *) ctr + 16;
        for (int i = 0; i < tag_len; i++)
        {
            tag[i] = ctx->buff[i] ^ ctx->Enc_y0[i];
        }


    }

    void sm4_bsro512_key_schedule(uint8_t* key, uint8_t BS_RK_512[32][8][64])
    {
        uint32_t rkey[32];
        // System parameter or family key
        const uint32_t FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };

        const uint32_t CK[32] = {
        0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
        0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
        0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
        0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
        0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
        0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
        0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
        0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
        };

        uint32_t K[36];
        uint32_t MK[4];
        GET_ULONG_BE( MK[0], key, 0 );
        GET_ULONG_BE( MK[1], key, 4 );
        GET_ULONG_BE( MK[2], key, 8 );
        GET_ULONG_BE( MK[3], key, 12 );

        K[0] = MK[0] ^ FK[0];
        K[1] = MK[1] ^ FK[1];
        K[2] = MK[2] ^ FK[2];
        K[3] = MK[3] ^ FK[3];

        for(int i = 0; i<32; i++)
        {
            K[i+4] = K[i] ^ (sm4CalciRK(K[i+1]^K[i+2]^K[i+3]^CK[i]));
            rkey[i] = K[i+4];
            //printf("rkey[%d]=%08x\n",i,rkey[i]);
        }

        for(int i = 0; i < 32; i++)//rkey的循环
        { 
            uint32_t t = 0x80000000;
            for(int j = 0; j < 32; j++)//rkey[i]的位的循环
            {   
                int tmp = j/8;//j/8向下取整，因为同一512位的寄存器中，每32bit是一样的，所以同时放在0，4，8，12，16，20，24，28...60的uint8_t中的
                if(rkey[i] & t)
                {   
                    BS_RK_512[i][j%8][0+tmp] = ~0;
                    BS_RK_512[i][j%8][4+tmp] = ~0;
                    BS_RK_512[i][j%8][8+tmp] = ~0;
                    BS_RK_512[i][j%8][12+tmp] = ~0;
                    BS_RK_512[i][j%8][16+tmp] = ~0;
                    BS_RK_512[i][j%8][20+tmp] = ~0;
                    BS_RK_512[i][j%8][24+tmp] = ~0;
                    BS_RK_512[i][j%8][28+tmp] = ~0;
                    BS_RK_512[i][j%8][32+tmp] = ~0;
                    BS_RK_512[i][j%8][36+tmp] = ~0;
                    BS_RK_512[i][j%8][40+tmp] = ~0;
                    BS_RK_512[i][j%8][44+tmp] = ~0;
                    BS_RK_512[i][j%8][48+tmp] = ~0;
                    BS_RK_512[i][j%8][52+tmp] = ~0;
                    BS_RK_512[i][j%8][56+tmp] = ~0;
                    BS_RK_512[i][j%8][60+tmp] = ~0;
                    
                }
                else
                {
                    BS_RK_512[i][j%8][0+tmp] = 0;
                    BS_RK_512[i][j%8][4+tmp] = 0;
                    BS_RK_512[i][j%8][8+tmp] = 0;
                    BS_RK_512[i][j%8][12+tmp] = 0;
                    BS_RK_512[i][j%8][16+tmp] = 0;
                    BS_RK_512[i][j%8][20+tmp] = 0;
                    BS_RK_512[i][j%8][24+tmp] = 0;
                    BS_RK_512[i][j%8][28+tmp] = 0;
                    BS_RK_512[i][j%8][32+tmp] = 0;
                    BS_RK_512[i][j%8][36+tmp] = 0;
                    BS_RK_512[i][j%8][40+tmp] = 0;
                    BS_RK_512[i][j%8][44+tmp] = 0;
                    BS_RK_512[i][j%8][48+tmp] = 0;
                    BS_RK_512[i][j%8][52+tmp] = 0;
                    BS_RK_512[i][j%8][56+tmp] = 0;
                    BS_RK_512[i][j%8][60+tmp] = 0;
                }
                
                t = t >> 1;
            }
        }
    }

    void sm4_bsro512_gcm_init(gcm_context *context, unsigned char *key,
    uint8_t BS_RK_512[32][8][64], unsigned char *iv)
    {
        //key_schedule
        sm4_bsro512_key_schedule(key,BS_RK_512);
        //compute table, init h and E(y0)

        uint8_t p_h[32],c_h[32];
        memset(p_h, 0, 32);//all 0
        memcpy(p_h+16, iv, 16);//iv||counter0
        memset(p_h+31, 1, 1);
        sm4_bsro512_ecb_encrypt(c_h,p_h,32,BS_RK_512);
        computeTable(context->T, c_h);
        memcpy(context->H, c_h, 16);
        memcpy(context->Enc_y0, c_h+16, 16);
    }

    void BSRO512_iteration(__m512i IN[32], __m512i BS_RK_512[32][8])
    {
        uint64_t t1 , t2;
        __m512i tmp;
        __m512i ymm[8];
        //四轮放在一起执行，减少32位移位操作
        for (int i = 0; i < 32; i+=4)
        {
            for (int j = 0; j < 8; j++)//32位异或操作
            {
                ymm[j] = IN[8+j] ^ IN[16+j] ^ IN[24+j] ^ BS_RK_512[i][j];
                //print_m256i(rk);
            }
            
            Sbox_BSRO512(ymm);//正确
        
            L_tran_512(ymm);

            for (int j = 0; j < 8; j++)//32位异或操作
            {
                IN[j] = _mm512_xor_si512(ymm[j],IN[j]);
            }

            for (int j = 0; j < 8; j++)//32位异或操作
            {
                ymm[j] = IN[j] ^ IN[16+j] ^ IN[24+j] ^ BS_RK_512[i+1][j];
            }
            
            Sbox_BSRO512(ymm);//正确
        
            L_tran_512(ymm);
            
            for (int j = 0; j < 8; j++)//32位异或操作
            {
                IN[j+8] = _mm512_xor_si512(ymm[j],IN[j+8]);
            }

            for (int j = 0; j < 8; j++)//32位异或操作
            {
                ymm[j] = IN[j] ^ IN[8+j] ^ IN[24+j] ^ BS_RK_512[i+2][j];
                //print_m256i(rk);
            }
            
            Sbox_BSRO512(ymm);//正确
        
            L_tran_512(ymm);
            
            for (int j = 0; j < 8; j++)//32位异或操作
            {
                IN[j+16] = _mm512_xor_si512(ymm[j],IN[j+16]);
            }

            for (int j = 0; j < 8; j++)//32位异或操作
            {
                ymm[j] = IN[j] ^ IN[8+j] ^ IN[16+j] ^ BS_RK_512[i+3][j];
                //print_m256i(rk);
            }
            
            Sbox_BSRO512(ymm);//正确
        
            L_tran_512(ymm);
            
            for (int j = 0; j < 8; j++)//32位异或操作
            {
                IN[j+24] = _mm512_xor_si512(ymm[j],IN[j+24]);
            }

        }
    
        for (int j = 0; j < 8; j++)//反序变换
        {
            tmp = IN[j];
            IN[j] = IN[j+24];
            IN[j+24] = tmp;
            tmp = IN[j+8];
            IN[j+8] = IN[j+16];
            IN[j+16] = tmp;
        }
    }

    static __m512i L_shuffle_512(__m512i data, int move)
    {
        __m512i swap;
        __m512i result;
        switch (move)
        {
        case 8:
            swap = _mm512_setr_epi8(1,2,3,0,5,6,7,4,9,10,11,8,13,14,15,12,1,2,3,0,5,6,7,4,9,10,11,8,13,14,15,12,
                                    1,2,3,0,5,6,7,4,9,10,11,8,13,14,15,12,1,2,3,0,5,6,7,4,9,10,11,8,13,14,15,12);
            result = _mm512_shuffle_epi8(data,swap);
            break;
        
        case 16:
            swap = _mm512_setr_epi8(2,3,0,1,6,7,4,5,10,11,8,9,14,15,12,13,2,3,0,1,6,7,4,5,10,11,8,9,14,15,12,13,
                                    2,3,0,1,6,7,4,5,10,11,8,9,14,15,12,13,2,3,0,1,6,7,4,5,10,11,8,9,14,15,12,13);
            result = _mm512_shuffle_epi8(data,swap);
            break;
        
        case 24:
            swap = _mm512_setr_epi8(3,0,1,2,7,4,5,6,11,8,9,10,15,12,13,14,3,0,1,2,7,4,5,6,11,8,9,10,15,12,13,14,
                                    3,0,1,2,7,4,5,6,11,8,9,10,15,12,13,14,3,0,1,2,7,4,5,6,11,8,9,10,15,12,13,14);
            result = _mm512_shuffle_epi8(data,swap);
            break;

        default:
            printf("\nvalues of move should be one of the numbers 8,16,24 \n");
            break;
        }
        return result;
    }

    void L_tran_512(__m512i *buf_512)
    {
        __m512i state[8];
        state[0] = buf_512[0]^buf_512[2]^L_shuffle_512(buf_512[2],8)^L_shuffle_512(buf_512[2],16)^L_shuffle_512(buf_512[0],24);
        state[1] = buf_512[1]^buf_512[3]^L_shuffle_512(buf_512[3],8)^L_shuffle_512(buf_512[3],16)^L_shuffle_512(buf_512[1],24);
        state[2] = buf_512[2]^buf_512[4]^L_shuffle_512(buf_512[4],8)^L_shuffle_512(buf_512[4],16)^L_shuffle_512(buf_512[2],24);
        state[3] = buf_512[3]^buf_512[5]^L_shuffle_512(buf_512[5],8)^L_shuffle_512(buf_512[5],16)^L_shuffle_512(buf_512[3],24); 
        state[4] = buf_512[4]^buf_512[6]^L_shuffle_512(buf_512[6],8)^L_shuffle_512(buf_512[6],16)^L_shuffle_512(buf_512[4],24);
        state[5] = buf_512[5]^buf_512[7]^L_shuffle_512(buf_512[7],8)^L_shuffle_512(buf_512[7],16)^L_shuffle_512(buf_512[5],24);
        state[6] = buf_512[6]^L_shuffle_512(buf_512[0],8)^L_shuffle_512(buf_512[0],16)^L_shuffle_512(buf_512[0],24)^L_shuffle_512(buf_512[6],24);
        state[7] = buf_512[7]^L_shuffle_512(buf_512[1],8)^L_shuffle_512(buf_512[1],16)^L_shuffle_512(buf_512[1],24)^L_shuffle_512(buf_512[7],24);

        for (int i = 0; i < 8; i++)
        {
            buf_512[i] = state[i];
        }
    }

    __m512i shiftLeft_512(__m512i input, int n) {
        // 将输入数据左移n位,n不大于32
        __m512i oldShifted = _mm512_slli_epi32(input, n);

        uint maskNum = 0;
        uint addNum = 0x80000000;
        for (int i = 0; i < n; i++)
        {
            maskNum = maskNum + addNum ;
            addNum = addNum >> 1;
        }
        // 获取最高n位的值
        __m512i highestBit = _mm512_and_si512(input, _mm512_set1_epi32(maskNum));
        __m512i swap = _mm512_setr_epi32(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0);
        highestBit = _mm512_permutexvar_epi32(swap,highestBit);//todo 可能可以用，不能用尝试shuffle
        // highestBit = _mm512_shuffle_epi32(highestBit,swap);// todo shuffle可能也有问题，不行就用两个256的拼接
        highestBit = _mm512_srli_epi32(highestBit,32-n);
        __m512i newShifted = _mm512_or_si512(oldShifted,highestBit);
        newShifted = _mm512_mask_blend_epi32(0b0111111111111111,oldShifted,newShifted);//todo 可能错
        return newShifted;
    }
    __m512i shiftRight_512(__m512i input, int n) {
        // 将输入数据右移n位,n不大于32
        __m512i oldShifted = _mm512_srli_epi32(input, n);

        uint maskNum = 0;
        uint addNum = 1;
        for (int i = 0; i < n; i++)
        {
            maskNum = maskNum + addNum ;
            addNum = addNum << 1;
        }
        // 获取最低n位的值
        __m512i lowestBit = _mm512_and_si512(input, _mm512_set1_epi32(maskNum));
        __m512i swap = _mm512_setr_epi32(15,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14);
        lowestBit = _mm512_permutexvar_epi32(swap,lowestBit);
        // lowestBit = _mm512_shuffle_epi32(lowestBit,swap);
        lowestBit = _mm512_slli_epi32(lowestBit,32-n);
        __m512i newShifted = _mm512_or_si512(oldShifted,lowestBit);
        newShifted = _mm512_mask_blend_epi32(0b1111111111111110,oldShifted,newShifted);
        return newShifted;
    }


    void Sbox_BSRO512(__m512i buf_512[8])
    {
        bits_512 sm4;

        sm4.b7 = buf_512[0];
        sm4.b6 = buf_512[1];
        sm4.b5 = buf_512[2];
        sm4.b4 = buf_512[3];
        sm4.b3 = buf_512[4];
        sm4.b2 = buf_512[5];
        sm4.b1 = buf_512[6];
        sm4.b0 = buf_512[7];

        Sm4_BSRO512_BoolFun(sm4,&buf_512[7],&buf_512[6],&buf_512[5],&buf_512[4],
            &buf_512[3],&buf_512[2],&buf_512[1],&buf_512[0]);
    }

    void BS_RO_512_PACK(__m512i IN[32], __m512i OUT[32])
    { 
        __m512i state[16];
        //lo32再lo64取出a1,lo32再hi64取出a2,hi32再lo64取出a3,hi32再hi64取出a4
        state[0] = _mm512_unpacklo_epi32(IN[0],IN[1]);//lo32
        state[1] = _mm512_unpacklo_epi32(IN[2],IN[3]);
        state[2] = _mm512_unpacklo_epi32(IN[4],IN[5]);
        state[3] = _mm512_unpacklo_epi32(IN[6],IN[7]);
        state[4] = _mm512_unpacklo_epi32(IN[8],IN[9]);
        state[5] = _mm512_unpacklo_epi32(IN[10],IN[11]);
        state[6] = _mm512_unpacklo_epi32(IN[12],IN[13]);
        state[7] = _mm512_unpacklo_epi32(IN[14],IN[15]);
        state[8] = _mm512_unpacklo_epi32(IN[16],IN[17]);
        state[9] = _mm512_unpacklo_epi32(IN[18],IN[19]);
        state[10] = _mm512_unpacklo_epi32(IN[20],IN[21]);
        state[11] = _mm512_unpacklo_epi32(IN[22],IN[23]);
        state[12] = _mm512_unpacklo_epi32(IN[24],IN[25]);
        state[13] = _mm512_unpacklo_epi32(IN[26],IN[27]);
        state[14] = _mm512_unpacklo_epi32(IN[28],IN[29]);
        state[15] = _mm512_unpacklo_epi32(IN[30],IN[31]);

        OUT[0] = _mm512_unpacklo_epi64(state[0],state[1]);//lo32再lo64取出a1
        OUT[1] = _mm512_unpacklo_epi64(state[2],state[3]);
        OUT[2] = _mm512_unpacklo_epi64(state[4],state[5]);
        OUT[3] = _mm512_unpacklo_epi64(state[6],state[7]);
        OUT[4] = _mm512_unpacklo_epi64(state[8],state[9]);
        OUT[5] = _mm512_unpacklo_epi64(state[10],state[11]);
        OUT[6] = _mm512_unpacklo_epi64(state[12],state[13]);
        OUT[7] = _mm512_unpacklo_epi64(state[14],state[15]);

        OUT[8] = _mm512_unpackhi_epi64(state[0],state[1]);//lo32再hi64取出a2
        OUT[9] = _mm512_unpackhi_epi64(state[2],state[3]);
        OUT[10] = _mm512_unpackhi_epi64(state[4],state[5]);
        OUT[11] = _mm512_unpackhi_epi64(state[6],state[7]);
        OUT[12] = _mm512_unpackhi_epi64(state[8],state[9]);
        OUT[13] = _mm512_unpackhi_epi64(state[10],state[11]);
        OUT[14] = _mm512_unpackhi_epi64(state[12],state[13]);
        OUT[15] = _mm512_unpackhi_epi64(state[14],state[15]);
        
        state[0] = _mm512_unpackhi_epi32(IN[0],IN[1]);//hi32
        state[1] = _mm512_unpackhi_epi32(IN[2],IN[3]);
        state[2] = _mm512_unpackhi_epi32(IN[4],IN[5]);
        state[3] = _mm512_unpackhi_epi32(IN[6],IN[7]);
        state[4] = _mm512_unpackhi_epi32(IN[8],IN[9]);
        state[5] = _mm512_unpackhi_epi32(IN[10],IN[11]);
        state[6] = _mm512_unpackhi_epi32(IN[12],IN[13]);
        state[7] = _mm512_unpackhi_epi32(IN[14],IN[15]);
        state[8] = _mm512_unpackhi_epi32(IN[16],IN[17]);
        state[9] = _mm512_unpackhi_epi32(IN[18],IN[19]);
        state[10] = _mm512_unpackhi_epi32(IN[20],IN[21]);
        state[11] = _mm512_unpackhi_epi32(IN[22],IN[23]);
        state[12] = _mm512_unpackhi_epi32(IN[24],IN[25]);
        state[13] = _mm512_unpackhi_epi32(IN[26],IN[27]);
        state[14] = _mm512_unpackhi_epi32(IN[28],IN[29]);
        state[15] = _mm512_unpackhi_epi32(IN[30],IN[31]);
        
        OUT[16] = _mm512_unpacklo_epi64(state[0],state[1]);//hi32再lo64取出a3
        OUT[17] = _mm512_unpacklo_epi64(state[2],state[3]);
        OUT[18] = _mm512_unpacklo_epi64(state[4],state[5]);
        OUT[19] = _mm512_unpacklo_epi64(state[6],state[7]);
        OUT[20] = _mm512_unpacklo_epi64(state[8],state[9]);
        OUT[21] = _mm512_unpacklo_epi64(state[10],state[11]);
        OUT[22] = _mm512_unpacklo_epi64(state[12],state[13]);
        OUT[23] = _mm512_unpacklo_epi64(state[14],state[15]);

        OUT[24] = _mm512_unpackhi_epi64(state[0],state[1]);//hi32再hi64取出a4
        OUT[25] = _mm512_unpackhi_epi64(state[2],state[3]);
        OUT[26] = _mm512_unpackhi_epi64(state[4],state[5]);
        OUT[27] = _mm512_unpackhi_epi64(state[6],state[7]);
        OUT[28] = _mm512_unpackhi_epi64(state[8],state[9]);
        OUT[29] = _mm512_unpackhi_epi64(state[10],state[11]);
        OUT[30] = _mm512_unpackhi_epi64(state[12],state[13]);
        OUT[31] = _mm512_unpackhi_epi64(state[14],state[15]);
    
    }

    void BS_RO_512_UNPACK(__m512i IN[32], __m512i OUT[32])
    { 
        __m512i state1[8];
        __m512i state2[8];
        //对传入的第一组和第二组（原128bit的第一组32bit和第二组32bit）进行lo32
        state1[0] = _mm512_unpacklo_epi32(IN[0],IN[8]);
        state1[1] = _mm512_unpacklo_epi32(IN[1],IN[9]);
        state1[2] = _mm512_unpacklo_epi32(IN[2],IN[10]);
        state1[3] = _mm512_unpacklo_epi32(IN[3],IN[11]);
        state1[4] = _mm512_unpacklo_epi32(IN[4],IN[12]);
        state1[5] = _mm512_unpacklo_epi32(IN[5],IN[13]);
        state1[6] = _mm512_unpacklo_epi32(IN[6],IN[14]);
        state1[7] = _mm512_unpacklo_epi32(IN[7],IN[15]);

        //第三组和第四组进行lo32
        state2[0] = _mm512_unpacklo_epi32(IN[16],IN[24]);
        state2[1] = _mm512_unpacklo_epi32(IN[17],IN[25]);
        state2[2] = _mm512_unpacklo_epi32(IN[18],IN[26]);
        state2[3] = _mm512_unpacklo_epi32(IN[19],IN[27]);
        state2[4] = _mm512_unpacklo_epi32(IN[20],IN[28]);
        state2[5] = _mm512_unpacklo_epi32(IN[21],IN[29]);
        state2[6] = _mm512_unpacklo_epi32(IN[22],IN[30]);
        state2[7] = _mm512_unpacklo_epi32(IN[23],IN[31]);

        //对state1和state2中的结果进行lo64取出a、b、i、j......注意OUT的下标，ab是0，cd是1，ef是2，gh是3，ij是4.......
        OUT[0] = _mm512_unpacklo_epi64(state1[0],state2[0]);
        OUT[4] = _mm512_unpacklo_epi64(state1[1],state2[1]);
        OUT[8] = _mm512_unpacklo_epi64(state1[2],state2[2]);
        OUT[12] = _mm512_unpacklo_epi64(state1[3],state2[3]);
        OUT[16] = _mm512_unpacklo_epi64(state1[4],state2[4]);
        OUT[20] = _mm512_unpacklo_epi64(state1[5],state2[5]);
        OUT[24] = _mm512_unpacklo_epi64(state1[6],state2[6]);
        OUT[28] = _mm512_unpacklo_epi64(state1[7],state2[7]);

        //对state1和state2中的结果进行hi64取出c、d、k、l......
        OUT[1] = _mm512_unpackhi_epi64(state1[0],state2[0]);
        OUT[5] = _mm512_unpackhi_epi64(state1[1],state2[1]);
        OUT[9] = _mm512_unpackhi_epi64(state1[2],state2[2]);
        OUT[13] = _mm512_unpackhi_epi64(state1[3],state2[3]);
        OUT[17] = _mm512_unpackhi_epi64(state1[4],state2[4]);
        OUT[21] = _mm512_unpackhi_epi64(state1[5],state2[5]);
        OUT[25] = _mm512_unpackhi_epi64(state1[6],state2[6]);
        OUT[29] = _mm512_unpackhi_epi64(state1[7],state2[7]);
        
        //对传入的第一组和第二组进行hi32
        state1[0] = _mm512_unpackhi_epi32(IN[0],IN[8]);
        state1[1] = _mm512_unpackhi_epi32(IN[1],IN[9]);
        state1[2] = _mm512_unpackhi_epi32(IN[2],IN[10]);
        state1[3] = _mm512_unpackhi_epi32(IN[3],IN[11]);
        state1[4] = _mm512_unpackhi_epi32(IN[4],IN[12]);
        state1[5] = _mm512_unpackhi_epi32(IN[5],IN[13]);
        state1[6] = _mm512_unpackhi_epi32(IN[6],IN[14]);
        state1[7] = _mm512_unpackhi_epi32(IN[7],IN[15]);

        //对传入的第三组和第四组进行hi3
        state2[0] = _mm512_unpackhi_epi32(IN[16],IN[24]);
        state2[1] = _mm512_unpackhi_epi32(IN[17],IN[25]);
        state2[2] = _mm512_unpackhi_epi32(IN[18],IN[26]);
        state2[3] = _mm512_unpackhi_epi32(IN[19],IN[27]);
        state2[4] = _mm512_unpackhi_epi32(IN[20],IN[28]);
        state2[5] = _mm512_unpackhi_epi32(IN[21],IN[29]);
        state2[6] = _mm512_unpackhi_epi32(IN[22],IN[30]);
        state2[7] = _mm512_unpackhi_epi32(IN[23],IN[31]);
        
        //对state1和state2中的结果进行lo64取出e、f、m、n......
        OUT[2] = _mm512_unpacklo_epi64(state1[0],state2[0]);
        OUT[6] = _mm512_unpacklo_epi64(state1[1],state2[1]);
        OUT[10] = _mm512_unpacklo_epi64(state1[2],state2[2]);
        OUT[14] = _mm512_unpacklo_epi64(state1[3],state2[3]);
        OUT[18] = _mm512_unpacklo_epi64(state1[4],state2[4]);
        OUT[22] = _mm512_unpacklo_epi64(state1[5],state2[5]);
        OUT[26] = _mm512_unpacklo_epi64(state1[6],state2[6]);
        OUT[30] = _mm512_unpacklo_epi64(state1[7],state2[7]);

        //对state1和state2中的结果进行hi64取出g、h、o、p......
        OUT[3] = _mm512_unpackhi_epi64(state1[0],state2[0]);
        OUT[7] = _mm512_unpackhi_epi64(state1[1],state2[1]);
        OUT[11] = _mm512_unpackhi_epi64(state1[2],state2[2]);
        OUT[15] = _mm512_unpackhi_epi64(state1[3],state2[3]);
        OUT[19] = _mm512_unpackhi_epi64(state1[4],state2[4]);
        OUT[23] = _mm512_unpackhi_epi64(state1[5],state2[5]);
        OUT[27] = _mm512_unpackhi_epi64(state1[6],state2[6]);
        OUT[31] = _mm512_unpackhi_epi64(state1[7],state2[7]);
    }

    void BS_RO_512_TRANS(__m512i IN[32], __m512i OUT[32])
    {   
        __m512i temp, M;
        uint8_t k = 0;
        uint8_t r = 0;
        uint64_t m[3][8]={
            {0x5555555555555555,0x5555555555555555,0x5555555555555555,0x5555555555555555,
            0x5555555555555555,0x5555555555555555,0x5555555555555555,0x5555555555555555},
            {0x3333333333333333,0x3333333333333333,0x3333333333333333,0x3333333333333333,
            0x3333333333333333,0x3333333333333333,0x3333333333333333,0x3333333333333333},
            {0x0f0f0f0f0f0f0f0f,0x0f0f0f0f0f0f0f0f,0x0f0f0f0f0f0f0f0f,0x0f0f0f0f0f0f0f0f,
            0x0f0f0f0f0f0f0f0f,0x0f0f0f0f0f0f0f0f,0x0f0f0f0f0f0f0f0f,0x0f0f0f0f0f0f0f0f}
        };//0x55 = 01010101 0x33 = 00110011 0x0f = 00001111

        for (int round = 0; round < 4; round++)//每轮处理8*256个，一共传入32*256bit的数据
        {   
            for (int j = 0; j < 3; j++)
            {
                k = 1 << j;
                for (int i = 0; i < 8; i++)
                {
                    r = ((i - i % k) << 1) + (i % k);
                    if (r + k > 7) break;
                    M = _mm512_loadu_si512((__m512i*)m[j]);
                    temp = (IN[round * 8 + r] & shiftLeft_512(M,k)) ^ shiftRight_512((IN[round * 8 + r + k] & shiftLeft_512(M,k)),k);       
                    IN[round * 8 + r + k] = shiftLeft_512((IN[round * 8 + r] & M),k) ^ (IN[round * 8 + r + k] & M);
                    IN[round * 8 + r] = temp;
                }
            }
            for (int i = 0; i < 8; i++)
            {
                _mm512_storeu_si512(OUT + (round * 8 + i), IN[round * 8 + i]);
            }
        }
    }


    void sm4_bsro512_enc(__m512i IN[32],__m512i OUT[32],__m512i rk[32][8])
    {
        __m512i state[32];
        BS_RO_512_PACK(IN,state);//数据打包
        // printf("\nafter-pack:\n");
        // dump_hex(state,2048);
        BS_RO_512_TRANS(state,IN);//数据转置
        // printf("\nafter-tran:\n");
        // dump_hex(IN,2048);
        BSRO512_iteration(IN,rk);
        // printf("\nafter-sbox:\n");
        // dump_hex(IN,1024);
        BS_RO_512_TRANS(IN,state);//数据逆转置
        // printf("\nstate:\n");
        // dump_hex(state,2048);
        BS_RO_512_UNPACK(state,OUT);//数据逆打包
        // printf("\nout:\n");
        // dump_hex(OUT,1024);
    }

    void Sm4_BSRO512_BoolFun(bits_512 in, __m512i *out0, __m512i *out1, __m512i *out2, __m512i *out3, __m512i *out4, __m512i *out5, __m512i *out6, __m512i *out7){
            __m512i y_t[21], t_t[8], t_m[46], y_m[18], t_b[30];
            y_t[18] = in.b2 ^in.b6;
            t_t[ 0] = in.b3 ^in.b4;
            t_t[ 1] = in.b2 ^in.b7;
            t_t[ 2] = in.b7 ^y_t[18];
            t_t[ 3] = in.b1 ^t_t[ 1];
            t_t[ 4] = in.b6 ^in.b7;
            t_t[ 5] = in.b0 ^y_t[18];
            t_t[ 6] = in.b3 ^in.b6;
            y_t[10] = in.b1 ^y_t[18];
            y_t[ 0] = in.b5 ^~ y_t[10];
            y_t[ 1] = t_t[ 0] ^t_t[ 3];
            y_t[ 2] = in.b0 ^t_t[ 0];
            y_t[ 4] = in.b0 ^t_t[ 3];
            y_t[ 3] = in.b3 ^y_t[ 4];
            y_t[ 5] = in.b5 ^t_t[ 5];
            y_t[ 6] = in.b0 ^~ in.b1;
            y_t[ 7] = t_t[ 0] ^~ y_t[10];
            y_t[ 8] = t_t[ 0] ^t_t[ 5];
            y_t[ 9] = in.b3;
            y_t[11] = t_t[ 0] ^t_t[ 4];
            y_t[12] = in.b5 ^t_t[ 4];
            y_t[13] = in.b5 ^~ y_t[ 1];
            y_t[14] = in.b4 ^~ t_t[ 2];
            y_t[15] = in.b1 ^~ t_t[ 6];
            y_t[16] = in.b0 ^~ t_t[ 2];
            y_t[17] = t_t[ 0] ^~ t_t[ 2];
            y_t[19] = in.b5 ^~ y_t[14];
            y_t[20] = in.b0 ^t_t[ 1];

        //The shared non-linear middle part for AES, AES^-1, and SM4
        t_m[ 0] = y_t[ 3] ^	 y_t[12];
            t_m[ 1] = y_t[ 9] &	 y_t[ 5];
            t_m[ 2] = y_t[17] &	 y_t[ 6];
            t_m[ 3] = y_t[10] ^	 t_m[ 1];
            t_m[ 4] = y_t[14] &	 y_t[ 0];
            t_m[ 5] = t_m[ 4] ^	 t_m[ 1];
            t_m[ 6] = y_t[ 3] &	 y_t[12];
            t_m[ 7] = y_t[16] &	 y_t[ 7];
            t_m[ 8] = t_m[ 0] ^	 t_m[ 6];
            t_m[ 9] = y_t[15] &	 y_t[13];
            t_m[10] = t_m[ 9] ^	 t_m[ 6];
            t_m[11] = y_t[ 1] &	 y_t[11];
            t_m[12] = y_t[ 4] &	 y_t[20];
            t_m[13] = t_m[12] ^	 t_m[11];
            t_m[14] = y_t[ 2] &	 y_t[ 8];
            t_m[15] = t_m[14] ^	 t_m[11];
            t_m[16] = t_m[ 3] ^	 t_m[ 2];
            t_m[17] = t_m[ 5] ^	 y_t[18];
            t_m[18] = t_m[ 8] ^	 t_m[ 7];
            t_m[19] = t_m[10] ^	 t_m[15];
            t_m[20] = t_m[16] ^	 t_m[13];
            t_m[21] = t_m[17] ^	 t_m[15];
            t_m[22] = t_m[18] ^	 t_m[13];
            t_m[23] = t_m[19] ^	 y_t[19];
            t_m[24] = t_m[22] ^	 t_m[23];
            t_m[25] = t_m[22] &	 t_m[20];
            t_m[26] = t_m[21] ^	 t_m[25];
            t_m[27] = t_m[20] ^	 t_m[21];
            t_m[28] = t_m[23] ^	 t_m[25];
            t_m[29] = t_m[28] &	 t_m[27];
            t_m[30] = t_m[26] &	 t_m[24];
            t_m[31] = t_m[20] &	 t_m[23];
            t_m[32] = t_m[27] &	 t_m[31];
            t_m[33] = t_m[27] ^	 t_m[25];
            t_m[34] = t_m[21] &	 t_m[22];
            t_m[35] = t_m[24] &	 t_m[34];
            t_m[36] = t_m[24] ^	 t_m[25];
            t_m[37] = t_m[21] ^	 t_m[29];
            t_m[38] = t_m[32] ^	 t_m[33];
            t_m[39] = t_m[23] ^	 t_m[30];
            t_m[40] = t_m[35] ^	 t_m[36];
            t_m[41] = t_m[38] ^	 t_m[40];
            t_m[42] = t_m[37] ^	 t_m[39];
            t_m[43] = t_m[37] ^	 t_m[38];
            t_m[44] = t_m[39] ^	 t_m[40];
            t_m[45] = t_m[42] ^	 t_m[41];
            y_m[ 0] = t_m[38] &	 y_t[ 7];
            y_m[ 1] = t_m[37] &	 y_t[13];
            y_m[ 2] = t_m[42] &	 y_t[11];
            y_m[ 3] = t_m[45] &	 y_t[20];
            y_m[ 4] = t_m[41] &	 y_t[ 8];
            y_m[ 5] = t_m[44] &	 y_t[ 9];
            y_m[ 6] = t_m[40] &	 y_t[17];
            y_m[ 7] = t_m[39] &	 y_t[14];
            y_m[ 8] = t_m[43] &	 y_t[ 3];
            y_m[ 9] = t_m[38] &	 y_t[16];
            y_m[10] = t_m[37] &	 y_t[15];
            y_m[11] = t_m[42] &	 y_t[ 1];
            y_m[12] = t_m[45] &	 y_t[ 4];
            y_m[13] = t_m[41] &	 y_t[ 2];
            y_m[14] = t_m[44] &	 y_t[ 5];
            y_m[15] = t_m[40] &	 y_t[ 6];
            y_m[16] = t_m[39] &	 y_t[ 0];
            y_m[17] = t_m[43] &	 y_t[12];

    //bottom(outer) linear layer for sm4
        t_b[ 0] = y_m[ 4] ^	 y_m[ 7];
            t_b[ 1] = y_m[13] ^	 y_m[15];
            t_b[ 2] = y_m[ 2] ^	 y_m[16];
            t_b[ 3] = y_m[ 6] ^	 t_b[ 0];
            t_b[ 4] = y_m[12] ^	 t_b[ 1];
            t_b[ 5] = y_m[ 9] ^	 y_m[10];
            t_b[ 6] = y_m[11] ^	 t_b[ 2];
            t_b[ 7] = y_m[ 1] ^	 t_b[ 4];
            t_b[ 8] = y_m[ 0] ^	 y_m[17];
            t_b[ 9] = y_m[ 3] ^	 y_m[17];
            t_b[10] = y_m[ 8] ^	 t_b[ 3];
            t_b[11] = t_b[ 2] ^	 t_b[ 5];
            t_b[12] = y_m[14] ^	 t_b[ 6];
            t_b[13] = t_b[ 7] ^	 t_b[ 9];
            t_b[14] = y_m[ 0] ^	 y_m[ 6];
            t_b[15] = y_m[ 7] ^	 y_m[16];
            t_b[16] = y_m[ 5] ^	 y_m[13];
            t_b[17] = y_m[ 3] ^	 y_m[15];
            t_b[18] = y_m[10] ^	 y_m[12];
            t_b[19] = y_m[ 9] ^	 t_b[ 1];
            t_b[20] = y_m[ 4] ^	 t_b[ 4];
            t_b[21] = y_m[14] ^	 t_b[ 3];
            t_b[22] = y_m[16] ^	 t_b[ 5];
            t_b[23] = t_b[ 7] ^	 t_b[14];
            t_b[24] = t_b[ 8] ^	 t_b[11];
            t_b[25] = t_b[ 0] ^	 t_b[12];
            t_b[26] = t_b[17] ^	 t_b[ 3];
            t_b[27] = t_b[18] ^	 t_b[10];
            t_b[28] = t_b[19] ^	 t_b[ 6];
            t_b[29] = t_b[ 8] ^	 t_b[10];
            *out0 = t_b[11] ^~ t_b[13];
            *out1 = t_b[15] ^~ t_b[23];
            *out2 = t_b[20] ^	 t_b[24];
            *out3 = t_b[16] ^	 t_b[25];
            *out4 = t_b[26] ^~ t_b[22];
            *out5 = t_b[21] ^	 t_b[13];
            *out6 = t_b[27] ^~ t_b[12];
            *out7 = t_b[28] ^~ t_b[29];
    }

    size_t test_sm4_bsro512_gcm_crypt_loop(size_t size){

        size_t count = 0;
        uint8_t rk[32][8][64] = {0};
        gcm_context *ctx = gcm_init();
        sm4_bsro512_gcm_init(ctx,test_key,rk,test_iv_enc);
        for (count = 0; run && count < 0xffffffffffffffff; count++)
        {
            sm4_bsro512_gcm_encrypt(test_output, test_input, size, rk, test_iv_enc, 16, test_aad, 23, test_tag, 16, test_output);
        }
        return count;
    }

    size_t test_sm4_bsro512_ctr_crypt_loop(size_t size){
        size_t count = 0;
        uint8_t rk[32][8][64] = {0};
        sm4_bsro512_key_schedule(test_key,rk);
        for (count = 0; run && count < 0xffffffffffffffff; count++)
        {
            sm4_bsro512_ctr_encrypt(test_output, test_input, size, rk, test_iv_enc);
        }
        
        return count;
    }

    size_t test_sm4_bsro512_ecb_crypt_loop(size_t size){
        size_t count = 0;
        uint8_t rk[32][8][64] = {0};
        sm4_bsro512_key_schedule(test_key,rk);
        for (count = 0; run && count < 0xffffffffffffffff; count++)
        {
            sm4_bsro512_ecb_encrypt(test_output, test_input, size, rk);
        }
        
        return count;
    }


    void performance_test_sm4_bsro512()
    {
        size_t size[6] = {16, 64, 256, 1024, 8192, 16384};
        printf("\nsm4_bsro512_ecb:\n");
        performance_test_enc(test_sm4_bsro512_ecb_crypt_loop, size, 6, 3);
        printf("\nsm4_bsro512_ctr:\n");
        performance_test_enc(test_sm4_bsro512_ctr_crypt_loop, size, 6, 3);
        printf("\nsm4_bsro512_gcm:\n");
        performance_test_enc(test_sm4_bsro512_gcm_crypt_loop, size, 6, 3);
    }

    void benchmark_sm4_bs_ro_512_ecb_encrypt(uint8_t *plain, uint8_t *cipher,int size,uint8_t rk[32][8][64])
    {
        int turns = 10000;
        clock_t t = clock();
        for(int i=0; i<turns; i++)
        {
            sm4_bsro512_ecb_encrypt(cipher,plain,size,rk);
        }
        clock_t t1 = clock();
        double tt = (double)(t1 - t) / (CLOCKS_PER_SEC*turns);
        double speed = (double) size / (1024 * 1024 * tt);
        // dump_hex(cipher,size);
        printf("BSRO512_SM4_ECB_encrypt>>> blocks: %d, time: %f s, speed: %f Mb/s\n", size/16, tt, speed*8);
    }

    void benchmark_sm4_bs_ro_512_ctr_encrypt(uint8_t *plain, uint8_t *cipher,int size,uint8_t rk[32][8][64],uint8_t * iv)
    {
        int turns = 10000;
        clock_t t = clock();
        for(int i=0; i<turns; i++)
        {
            sm4_bsro512_ctr_encrypt(cipher,plain,size,rk,iv);
        }
        clock_t t1 = clock();
        double tt = (double)(t1 - t) / (CLOCKS_PER_SEC*turns);
        double speed = (double) size / (1024 * 1024 * tt);
        // dump_hex(cipher,size);
        printf("BSRO512_SM4_CTR_encrypt>>> blocks: %d, time: %f s, speed: %f Mb/s\n", size/16, tt, speed*8);
    }
    void benchmark_sm4_bs_ro_512_gcm_encrypt(uint8_t *plain, uint8_t *cipher,int size,uint8_t rk[32][8][64],
        uint8_t * iv, int iv_len, uint8_t *add ,int add_len,
        uint8_t *tag, int tag_len, uint8_t T[][256][16])
    {
        int turns = 10000;
        clock_t t = clock();
        for(int i=0; i<turns; i++)
        {
            sm4_bsro512_gcm_encrypt(cipher,plain,size,rk,iv,iv_len,add,add_len,
                tag,tag_len,T);
        }
        double tt = (double)(clock() - t) / (CLOCKS_PER_SEC*turns);
        double speed = (double) size / (1024 * 1024 * tt);
        // dump_hex(cipher,size);
        printf("BSRO512_SM4_GCM_encrypt>>> blocks: %d, time: %f s, speed: %f Mb/s\n", size/16, tt, speed*8);
    }

#endif

#if defined(WBCRYPTO_SM4_BS_RO_NEON)
    #define SET8x16(res, e0, e1, e2, e3, e4, e5, e6, e7, e8, e9, e10, e11, e12, e13, e14, e15)                     \
    __asm__ __volatile__ (                                  \
        "mov %[r].b[0], %w[x]        \n\t"                  \
        "mov %[r].b[1], %w[y]        \n\t"                  \
        "mov %[r].b[2], %w[z]        \n\t"                  \
        "mov %[r].b[3], %w[k]        \n\t"                  \
        "mov %[r].b[4], %w[x0]        \n\t"                  \
        "mov %[r].b[5], %w[y0]        \n\t"                  \
        "mov %[r].b[6], %w[z0]        \n\t"                  \
        "mov %[r].b[7], %w[k0]        \n\t"                  \
        "mov %[r].b[8], %w[x1]        \n\t"                  \
        "mov %[r].b[9], %w[y1]        \n\t"                  \
        "mov %[r].b[10], %w[z1]        \n\t"                  \
        "mov %[r].b[11], %w[k1]        \n\t"                  \
        "mov %[r].b[12], %w[x2]        \n\t"                  \
        "mov %[r].b[13], %w[y2]        \n\t"                  \
        "mov %[r].b[14], %w[z2]        \n\t"                  \
        "mov %[r].b[15], %w[k2]        \n\t"                  \
        :[r]"=w"(res)                                       \
        :[x]"r"(e0), [y]"r"(e1), [z]"r"(e2), [k]"r"(e3), [x0]"r"(e4), [y0]"r"(e5), [z0]"r"(e6), [k0]"r"(e7), [x1]"r"(e8), [y1]"r"(e9), [z1]"r"(e10), [k1]"r"(e11), [x2]"r"(e12), [y2]"r"(e13), [z2]"r"(e14), [k2]"r"(e15)     \
    );
    #define SET32x4(res, e0, e1, e2, e3)                     \
    __asm__ __volatile__ (                                  \
        "mov %[r].s[0], %w[x]        \n\t"                  \
        "mov %[r].s[1], %w[y]        \n\t"                  \
        "mov %[r].s[2], %w[z]        \n\t"                  \
        "mov %[r].s[3], %w[k]        \n\t"                  \
        :[r]"=w"(res)                                       \
        :[x]"r"(e0), [y]"r"(e1), [z]"r"(e2), [k]"r"(e3)     \
    );

    static __m128i L_shuffle_neon(__m128i data, int move)
    {
        __m128i swap;
        __m128i result;
        switch (move)
        {
        case 8:
            SET8x16(swap.vect_u8,1,2,3,0,5,6,7,4,9,10,11,8,13,14,15,12);
            result.vect_u8 = vqtbl1q_u8(data.vect_u8, swap.vect_u8);//todo maybe error 
            break;
        
        case 16:
            SET8x16(swap.vect_u8,2,3,0,1,6,7,4,5,10,11,8,9,14,15,12,13);
            result.vect_u8 = vqtbl1q_u8(data.vect_u8, swap.vect_u8);
            break;
        
        case 24:
            SET8x16(swap.vect_u8,3,0,1,2,7,4,5,6,11,8,9,10,15,12,13,14);
            result.vect_u8 = vqtbl1q_u8(data.vect_u8, swap.vect_u8);
            break;

        default:
            printf("\nvalues of move should be one of the numbers 8,16,24 \n");
            break;
        }
        return result;
    }

    void L_tran_neon(__m128i *buf)
    {
        __m128i state[8];
        state[0].vect_u32 = buf[0].vect_u32 ^ buf[2].vect_u32 ^ L_shuffle_neon(buf[2],8).vect_u32 ^ L_shuffle_neon(buf[2],16).vect_u32 ^ L_shuffle_neon(buf[0],24).vect_u32;
        state[1].vect_u32 = buf[1].vect_u32 ^ buf[3].vect_u32 ^ L_shuffle_neon(buf[3],8).vect_u32 ^ L_shuffle_neon(buf[3],16).vect_u32 ^ L_shuffle_neon(buf[1],24).vect_u32;
        state[2].vect_u32 = buf[2].vect_u32 ^ buf[4].vect_u32 ^ L_shuffle_neon(buf[4],8).vect_u32 ^ L_shuffle_neon(buf[4],16).vect_u32 ^ L_shuffle_neon(buf[2],24).vect_u32;
        state[3].vect_u32 = buf[3].vect_u32 ^ buf[5].vect_u32 ^ L_shuffle_neon(buf[5],8).vect_u32 ^ L_shuffle_neon(buf[5],16).vect_u32 ^ L_shuffle_neon(buf[3],24).vect_u32; 
        state[4].vect_u32 = buf[4].vect_u32 ^ buf[6].vect_u32 ^ L_shuffle_neon(buf[6],8).vect_u32 ^ L_shuffle_neon(buf[6],16).vect_u32 ^ L_shuffle_neon(buf[4],24).vect_u32;
        state[5].vect_u32 = buf[5].vect_u32 ^ buf[7].vect_u32 ^ L_shuffle_neon(buf[7],8).vect_u32 ^ L_shuffle_neon(buf[7],16).vect_u32 ^ L_shuffle_neon(buf[5],24).vect_u32;
        state[6].vect_u32 = buf[6].vect_u32 ^ L_shuffle_neon(buf[0],8).vect_u32 ^ L_shuffle_neon(buf[0],16).vect_u32 ^ L_shuffle_neon(buf[0],24).vect_u32 ^ L_shuffle_neon(buf[6],24).vect_u32;
        state[7].vect_u32 = buf[7].vect_u32 ^ L_shuffle_neon(buf[1],8).vect_u32 ^ L_shuffle_neon(buf[1],16).vect_u32 ^ L_shuffle_neon(buf[1],24).vect_u32 ^ L_shuffle_neon(buf[7],24).vect_u32;

        for (int i = 0; i < 8; i++)
        {
            buf[i] = state[i];
        }
    }

    __m128i shiftLeft(__m128i input, int n) {
        // 将输入数据左移n位,n不大于32
        __m128i oldShifted;
        int32x4_t vect_imm = vdupq_n_u32(n);
        oldShifted.vect_u32 = vshlq_u32(input.vect_u32, vect_imm);
        uint32_t maskNum = 0;
        uint32_t addNum = 0x80000000;
        for (int i = 0; i < n; i++)
        {
            maskNum = maskNum + addNum ;
            addNum = addNum >> 1;
        }

        // 获取最高n位的值
        __m128i highestBit;
        highestBit.vect_u32 = vandq_u32(input.vect_u32, vdupq_n_u32(maskNum));
        uint32_t data[4] = {0};
        uint32_t tmp = 0;
        vst1q_u32(data,highestBit.vect_u32);
        tmp = data[0];
        data[0] = data[1];
        data[1] = data[2];
        data[2] = data[3];
        data[3] = tmp; 
        highestBit.vect_u32 = vld1q_u32(data);

        vect_imm = vdupq_n_u32(-(32-n));
        highestBit.vect_u32 = vshlq_u32(highestBit.vect_u32,vect_imm);

        __m128i newShifted;
        newShifted.vect_u32 = vorrq_u32(oldShifted.vect_u32,highestBit.vect_u32);
        uint32_t newData[4] = {0};
        uint32_t oldData[4] = {0};

        vst1q_u32(newData,newShifted.vect_u32);
        vst1q_u32(oldData,oldShifted.vect_u32);
        newData[0] = oldData[0];
        newShifted.vect_u32 = vld1q_u32(newData);
        return newShifted;
    }
    __m128i shiftRight(__m128i input, int n) {
        // 将输入数据右移n位,n不大于32
        int32x4_t vect_imm = vdupq_n_u32(-n);
        __m128i oldShifted;
        oldShifted.vect_u32 = vshlq_u32(input.vect_u32,vect_imm);

        uint32_t maskNum = 0;
        uint32_t addNum = 1;
        for (int i = 0; i < n; i++)
        {
            maskNum = maskNum + addNum ;
            addNum = addNum << 1;
        }

        // 获取最低n位的值
        __m128i lowestBit;
        lowestBit.vect_u32 = vandq_u32(input.vect_u32, vdupq_n_u32(maskNum));
        uint32_t data[4] = {0};
        uint32_t tmp = 0;
        vst1q_u32(data,lowestBit.vect_u32);
        tmp = data[3];
        data[3] = data[2];
        data[2] = data[1];
        data[1] = data[0];
        data[0] = tmp; 
        lowestBit.vect_u32 = vld1q_u32(data);
        vect_imm = vdupq_n_u32(32-n);
        lowestBit.vect_u32 = vshlq_u32(lowestBit.vect_u32, vect_imm);

        __m128i newShifted;
        newShifted.vect_u32 = vorrq_u32(oldShifted.vect_u32,lowestBit.vect_u32);
        uint32_t newData[4] = {0};
        uint32_t oldData[4] = {0};

        vst1q_u32(newData,newShifted.vect_u32);
        vst1q_u32(oldData,oldShifted.vect_u32);
        newData[4] = oldData[4];
        newShifted.vect_u32 = vld1q_u32(newData);
        return newShifted;
    }
     
    void Sm4_BSRO_NEON_BoolFun(bits_neon in, __m128i buf[8]){
            __m128i y_t[21], t_t[8], t_m[46], y_m[18], t_b[30];
            y_t[18].vect_u32 = in.b2.vect_u32 ^in.b6.vect_u32;
            t_t[ 0].vect_u32 = in.b3.vect_u32 ^in.b4.vect_u32;
            t_t[ 1].vect_u32 = in.b2.vect_u32 ^in.b7.vect_u32;
            t_t[ 2].vect_u32 = in.b7.vect_u32 ^y_t[18].vect_u32;
            t_t[ 3].vect_u32 = in.b1.vect_u32 ^t_t[ 1].vect_u32;
            t_t[ 4].vect_u32 = in.b6.vect_u32 ^in.b7.vect_u32;
            t_t[ 5].vect_u32 = in.b0.vect_u32 ^y_t[18].vect_u32;
            t_t[ 6].vect_u32 = in.b3.vect_u32 ^in.b6.vect_u32;
            y_t[10].vect_u32 = in.b1.vect_u32 ^y_t[18].vect_u32;
            y_t[ 0].vect_u32 = in.b5.vect_u32 ^~ y_t[10].vect_u32;
            y_t[ 1].vect_u32 = t_t[ 0].vect_u32 ^t_t[ 3].vect_u32;
            y_t[ 2].vect_u32 = in.b0.vect_u32 ^t_t[ 0].vect_u32;
            y_t[ 4].vect_u32 = in.b0.vect_u32 ^t_t[ 3].vect_u32;
            y_t[ 3].vect_u32 = in.b3.vect_u32 ^y_t[ 4].vect_u32;
            y_t[ 5].vect_u32 = in.b5.vect_u32 ^t_t[ 5].vect_u32;
            y_t[ 6].vect_u32 = in.b0.vect_u32 ^~ in.b1.vect_u32;
            y_t[ 7].vect_u32 = t_t[ 0].vect_u32 ^~ y_t[10].vect_u32;
            y_t[ 8].vect_u32 = t_t[ 0].vect_u32 ^t_t[ 5].vect_u32;
            y_t[ 9] = in.b3;
            y_t[11].vect_u32 = t_t[ 0].vect_u32 ^t_t[ 4].vect_u32;
            y_t[12].vect_u32 = in.b5.vect_u32 ^t_t[ 4].vect_u32;
            y_t[13].vect_u32 = in.b5.vect_u32 ^~ y_t[ 1].vect_u32;
            y_t[14].vect_u32 = in.b4.vect_u32 ^~ t_t[ 2].vect_u32;
            y_t[15].vect_u32 = in.b1.vect_u32 ^~ t_t[ 6].vect_u32;
            y_t[16].vect_u32 = in.b0.vect_u32 ^~ t_t[ 2].vect_u32;
            y_t[17].vect_u32 = t_t[ 0].vect_u32 ^~ t_t[ 2].vect_u32;
            y_t[19].vect_u32 = in.b5.vect_u32 ^~ y_t[14].vect_u32;
            y_t[20].vect_u32 = in.b0.vect_u32 ^t_t[ 1].vect_u32;

        //The shared non-linear middle part for AES, AES^-1, and SM4
        t_m[ 0].vect_u32 = y_t[ 3].vect_u32 ^	 y_t[12].vect_u32;
            t_m[ 1].vect_u32 = y_t[ 9].vect_u32 &	 y_t[ 5].vect_u32;
            t_m[ 2].vect_u32 = y_t[17].vect_u32 &	 y_t[ 6].vect_u32;
            t_m[ 3].vect_u32 = y_t[10].vect_u32 ^	 t_m[ 1].vect_u32;
            t_m[ 4].vect_u32 = y_t[14].vect_u32 &	 y_t[ 0].vect_u32;
            t_m[ 5].vect_u32 = t_m[ 4].vect_u32 ^	 t_m[ 1].vect_u32;
            t_m[ 6].vect_u32 = y_t[ 3].vect_u32 &	 y_t[12].vect_u32;
            t_m[ 7].vect_u32 = y_t[16].vect_u32 &	 y_t[ 7].vect_u32;
            t_m[ 8].vect_u32 = t_m[ 0].vect_u32 ^	 t_m[ 6].vect_u32;
            t_m[ 9].vect_u32 = y_t[15].vect_u32 &	 y_t[13].vect_u32;
            t_m[10].vect_u32 = t_m[ 9].vect_u32 ^	 t_m[ 6].vect_u32;
            t_m[11].vect_u32 = y_t[ 1].vect_u32 &	 y_t[11].vect_u32;
            t_m[12].vect_u32 = y_t[ 4].vect_u32 &	 y_t[20].vect_u32;
            t_m[13].vect_u32 = t_m[12].vect_u32 ^	 t_m[11].vect_u32;
            t_m[14].vect_u32 = y_t[ 2].vect_u32 &	 y_t[ 8].vect_u32;
            t_m[15].vect_u32 = t_m[14].vect_u32 ^	 t_m[11].vect_u32;
            t_m[16].vect_u32 = t_m[ 3].vect_u32 ^	 t_m[ 2].vect_u32;
            t_m[17].vect_u32 = t_m[ 5].vect_u32 ^	 y_t[18].vect_u32;
            t_m[18].vect_u32 = t_m[ 8].vect_u32 ^	 t_m[ 7].vect_u32;
            t_m[19].vect_u32 = t_m[10].vect_u32 ^	 t_m[15].vect_u32;
            t_m[20].vect_u32 = t_m[16].vect_u32 ^	 t_m[13].vect_u32;
            t_m[21].vect_u32 = t_m[17].vect_u32 ^	 t_m[15].vect_u32;
            t_m[22].vect_u32 = t_m[18].vect_u32 ^	 t_m[13].vect_u32;
            t_m[23].vect_u32 = t_m[19].vect_u32 ^	 y_t[19].vect_u32;
            t_m[24].vect_u32 = t_m[22].vect_u32 ^	 t_m[23].vect_u32;
            t_m[25].vect_u32 = t_m[22].vect_u32 &	 t_m[20].vect_u32;
            t_m[26].vect_u32 = t_m[21].vect_u32 ^	 t_m[25].vect_u32;
            t_m[27].vect_u32 = t_m[20].vect_u32 ^	 t_m[21].vect_u32;
            t_m[28].vect_u32 = t_m[23].vect_u32 ^	 t_m[25].vect_u32;
            t_m[29].vect_u32 = t_m[28].vect_u32 &	 t_m[27].vect_u32;
            t_m[30].vect_u32 = t_m[26].vect_u32 &	 t_m[24].vect_u32;
            t_m[31].vect_u32 = t_m[20].vect_u32 &	 t_m[23].vect_u32;
            t_m[32].vect_u32 = t_m[27].vect_u32 &	 t_m[31].vect_u32;
            t_m[33].vect_u32 = t_m[27].vect_u32 ^	 t_m[25].vect_u32;
            t_m[34].vect_u32 = t_m[21].vect_u32 &	 t_m[22].vect_u32;
            t_m[35].vect_u32 = t_m[24].vect_u32 &	 t_m[34].vect_u32;
            t_m[36].vect_u32 = t_m[24].vect_u32 ^	 t_m[25].vect_u32;
            t_m[37].vect_u32 = t_m[21].vect_u32 ^	 t_m[29].vect_u32;
            t_m[38].vect_u32 = t_m[32].vect_u32 ^	 t_m[33].vect_u32;
            t_m[39].vect_u32 = t_m[23].vect_u32 ^	 t_m[30].vect_u32;
            t_m[40].vect_u32 = t_m[35].vect_u32 ^	 t_m[36].vect_u32;
            t_m[41].vect_u32 = t_m[38].vect_u32 ^	 t_m[40].vect_u32;
            t_m[42].vect_u32 = t_m[37].vect_u32 ^	 t_m[39].vect_u32;
            t_m[43].vect_u32 = t_m[37].vect_u32 ^	 t_m[38].vect_u32;
            t_m[44].vect_u32 = t_m[39].vect_u32 ^	 t_m[40].vect_u32;
            t_m[45].vect_u32 = t_m[42].vect_u32 ^	 t_m[41].vect_u32;
            y_m[ 0].vect_u32 = t_m[38].vect_u32 &	 y_t[ 7].vect_u32;
            y_m[ 1].vect_u32 = t_m[37].vect_u32 &	 y_t[13].vect_u32;
            y_m[ 2].vect_u32 = t_m[42].vect_u32 &	 y_t[11].vect_u32;
            y_m[ 3].vect_u32 = t_m[45].vect_u32 &	 y_t[20].vect_u32;
            y_m[ 4].vect_u32 = t_m[41].vect_u32 &	 y_t[ 8].vect_u32;
            y_m[ 5].vect_u32 = t_m[44].vect_u32 &	 y_t[ 9].vect_u32;
            y_m[ 6].vect_u32 = t_m[40].vect_u32 &	 y_t[17].vect_u32;
            y_m[ 7].vect_u32 = t_m[39].vect_u32 &	 y_t[14].vect_u32;
            y_m[ 8].vect_u32 = t_m[43].vect_u32 &	 y_t[ 3].vect_u32;
            y_m[ 9].vect_u32 = t_m[38].vect_u32 &	 y_t[16].vect_u32;
            y_m[10].vect_u32 = t_m[37].vect_u32 &	 y_t[15].vect_u32;
            y_m[11].vect_u32 = t_m[42].vect_u32 &	 y_t[ 1].vect_u32;
            y_m[12].vect_u32 = t_m[45].vect_u32 &	 y_t[ 4].vect_u32;
            y_m[13].vect_u32 = t_m[41].vect_u32 &	 y_t[ 2].vect_u32;
            y_m[14].vect_u32 = t_m[44].vect_u32 &	 y_t[ 5].vect_u32;
            y_m[15].vect_u32 = t_m[40].vect_u32 &	 y_t[ 6].vect_u32;
            y_m[16].vect_u32 = t_m[39].vect_u32 &	 y_t[ 0].vect_u32;
            y_m[17].vect_u32 = t_m[43].vect_u32 &	 y_t[12].vect_u32;

    //bottom(outer) linear layer for sm4
        t_b[ 0].vect_u32 = y_m[ 4].vect_u32 ^	 y_m[ 7].vect_u32;
            t_b[ 1].vect_u32 = y_m[13].vect_u32 ^	 y_m[15].vect_u32;
            t_b[ 2].vect_u32 = y_m[ 2].vect_u32 ^	 y_m[16].vect_u32;
            t_b[ 3].vect_u32 = y_m[ 6].vect_u32 ^	 t_b[ 0].vect_u32;
            t_b[ 4].vect_u32 = y_m[12].vect_u32 ^	 t_b[ 1].vect_u32;
            t_b[ 5].vect_u32 = y_m[ 9].vect_u32 ^	 y_m[10].vect_u32;
            t_b[ 6].vect_u32 = y_m[11].vect_u32 ^	 t_b[ 2].vect_u32;
            t_b[ 7].vect_u32 = y_m[ 1].vect_u32 ^	 t_b[ 4].vect_u32;
            t_b[ 8].vect_u32 = y_m[ 0].vect_u32 ^	 y_m[17].vect_u32;
            t_b[ 9].vect_u32 = y_m[ 3].vect_u32 ^	 y_m[17].vect_u32;
            t_b[10].vect_u32 = y_m[ 8].vect_u32 ^	 t_b[ 3].vect_u32;
            t_b[11].vect_u32 = t_b[ 2].vect_u32 ^	 t_b[ 5].vect_u32;
            t_b[12].vect_u32 = y_m[14].vect_u32 ^	 t_b[ 6].vect_u32;
            t_b[13].vect_u32 = t_b[ 7].vect_u32 ^	 t_b[ 9].vect_u32;
            t_b[14].vect_u32 = y_m[ 0].vect_u32 ^	 y_m[ 6].vect_u32;
            t_b[15].vect_u32 = y_m[ 7].vect_u32 ^	 y_m[16].vect_u32;
            t_b[16].vect_u32 = y_m[ 5].vect_u32 ^	 y_m[13].vect_u32;
            t_b[17].vect_u32 = y_m[ 3].vect_u32 ^	 y_m[15].vect_u32;
            t_b[18].vect_u32 = y_m[10].vect_u32 ^	 y_m[12].vect_u32;
            t_b[19].vect_u32 = y_m[ 9].vect_u32 ^	 t_b[ 1].vect_u32;
            t_b[20].vect_u32 = y_m[ 4].vect_u32 ^	 t_b[ 4].vect_u32;
            t_b[21].vect_u32 = y_m[14].vect_u32 ^	 t_b[ 3].vect_u32;
            t_b[22].vect_u32 = y_m[16].vect_u32 ^	 t_b[ 5].vect_u32;
            t_b[23].vect_u32 = t_b[ 7].vect_u32 ^	 t_b[14].vect_u32;
            t_b[24].vect_u32 = t_b[ 8].vect_u32 ^	 t_b[11].vect_u32;
            t_b[25].vect_u32 = t_b[ 0].vect_u32 ^	 t_b[12].vect_u32;
            t_b[26].vect_u32 = t_b[17].vect_u32 ^	 t_b[ 3].vect_u32;
            t_b[27].vect_u32 = t_b[18].vect_u32 ^	 t_b[10].vect_u32;
            t_b[28].vect_u32 = t_b[19].vect_u32 ^	 t_b[ 6].vect_u32;
            t_b[29].vect_u32 = t_b[ 8].vect_u32 ^	 t_b[10].vect_u32;
            buf[7].vect_u32 = t_b[11].vect_u32 ^~ t_b[13].vect_u32;
            buf[6].vect_u32 = t_b[15].vect_u32 ^~ t_b[23].vect_u32;
            buf[5].vect_u32 = t_b[20].vect_u32 ^	 t_b[24].vect_u32;
            buf[4].vect_u32 = t_b[16].vect_u32 ^	 t_b[25].vect_u32;
            buf[3].vect_u32 = t_b[26].vect_u32 ^~ t_b[22].vect_u32;
            buf[2].vect_u32 = t_b[21].vect_u32 ^	 t_b[13].vect_u32;
            buf[1].vect_u32 = t_b[27].vect_u32 ^~ t_b[12].vect_u32;
            buf[0].vect_u32 = t_b[28].vect_u32 ^~ t_b[29].vect_u32;
    }


    void Sbox_BSRO_NEON(__m128i buf[8])
    {
        bits_neon sm4;

        sm4.b7 = buf[0];
        sm4.b6 = buf[1];
        sm4.b5 = buf[2];
        sm4.b4 = buf[3];
        sm4.b3 = buf[4];
        sm4.b2 = buf[5];
        sm4.b1 = buf[6];
        sm4.b0 = buf[7];

        Sm4_BSRO_NEON_BoolFun(sm4,buf);
    }

    void BS_RO_NEON_PACK(__m128i IN[32], __m128i OUT[32])
    { 
        __m128i state[16];
        //lo32再lo64取出a1,lo32再hi64取出a2,hi32再lo64取出a3,hi32再hi64取出a4
        state[0].vect_u32 = vzip1q_u32(IN[0].vect_u32,IN[1].vect_u32);//lo32
        state[1].vect_u32 = vzip1q_u32(IN[2].vect_u32,IN[3].vect_u32);
        state[2].vect_u32 = vzip1q_u32(IN[4].vect_u32,IN[5].vect_u32);
        state[3].vect_u32 = vzip1q_u32(IN[6].vect_u32,IN[7].vect_u32);
        state[4].vect_u32 = vzip1q_u32(IN[8].vect_u32,IN[9].vect_u32);
        state[5].vect_u32 = vzip1q_u32(IN[10].vect_u32,IN[11].vect_u32);
        state[6].vect_u32 = vzip1q_u32(IN[12].vect_u32,IN[13].vect_u32);
        state[7].vect_u32 = vzip1q_u32(IN[14].vect_u32,IN[15].vect_u32);
        state[8].vect_u32 = vzip1q_u32(IN[16].vect_u32,IN[17].vect_u32);
        state[9].vect_u32 = vzip1q_u32(IN[18].vect_u32,IN[19].vect_u32);
        state[10].vect_u32 = vzip1q_u32(IN[20].vect_u32,IN[21].vect_u32);
        state[11].vect_u32 = vzip1q_u32(IN[22].vect_u32,IN[23].vect_u32);
        state[12].vect_u32 = vzip1q_u32(IN[24].vect_u32,IN[25].vect_u32);
        state[13].vect_u32 = vzip1q_u32(IN[26].vect_u32,IN[27].vect_u32);
        state[14].vect_u32 = vzip1q_u32(IN[28].vect_u32,IN[29].vect_u32);
        state[15].vect_u32 = vzip1q_u32(IN[30].vect_u32,IN[31].vect_u32);
        

        OUT[0].vect_u64 = vzip1q_u64(state[0].vect_u64,state[1].vect_u64);//lo32再lo64取出a1
        OUT[1].vect_u64 = vzip1q_u64(state[2].vect_u64,state[3].vect_u64);
        OUT[2].vect_u64 = vzip1q_u64(state[4].vect_u64,state[5].vect_u64);
        OUT[3].vect_u64 = vzip1q_u64(state[6].vect_u64,state[7].vect_u64);
        OUT[4].vect_u64 = vzip1q_u64(state[8].vect_u64,state[9].vect_u64);
        OUT[5].vect_u64 = vzip1q_u64(state[10].vect_u64,state[11].vect_u64);
        OUT[6].vect_u64 = vzip1q_u64(state[12].vect_u64,state[13].vect_u64);
        OUT[7].vect_u64 = vzip1q_u64(state[14].vect_u64,state[15].vect_u64);

        OUT[8].vect_u64 = vzip2q_u64(state[0].vect_u64,state[1].vect_u64);//lo32再hi64取出a2
        OUT[9].vect_u64 = vzip2q_u64(state[2].vect_u64,state[3].vect_u64);
        OUT[10].vect_u64 = vzip2q_u64(state[4].vect_u64,state[5].vect_u64);
        OUT[11].vect_u64 = vzip2q_u64(state[6].vect_u64,state[7].vect_u64);
        OUT[12].vect_u64 = vzip2q_u64(state[8].vect_u64,state[9].vect_u64);
        OUT[13].vect_u64 = vzip2q_u64(state[10].vect_u64,state[11].vect_u64);
        OUT[14].vect_u64 = vzip2q_u64(state[12].vect_u64,state[13].vect_u64);
        OUT[15].vect_u64 = vzip2q_u64(state[14].vect_u64,state[15].vect_u64);
        
        state[0].vect_u32 = vzip2q_u32(IN[0].vect_u32,IN[1].vect_u32);//hi32
        state[1].vect_u32 = vzip2q_u32(IN[2].vect_u32,IN[3].vect_u32);
        state[2].vect_u32 = vzip2q_u32(IN[4].vect_u32,IN[5].vect_u32);
        state[3].vect_u32 = vzip2q_u32(IN[6].vect_u32,IN[7].vect_u32);
        state[4].vect_u32 = vzip2q_u32(IN[8].vect_u32,IN[9].vect_u32);
        state[5].vect_u32 = vzip2q_u32(IN[10].vect_u32,IN[11].vect_u32);
        state[6].vect_u32 = vzip2q_u32(IN[12].vect_u32,IN[13].vect_u32);
        state[7].vect_u32 = vzip2q_u32(IN[14].vect_u32,IN[15].vect_u32);
        state[8].vect_u32 = vzip2q_u32(IN[16].vect_u32,IN[17].vect_u32);
        state[9].vect_u32 = vzip2q_u32(IN[18].vect_u32,IN[19].vect_u32);
        state[10].vect_u32 = vzip2q_u32(IN[20].vect_u32,IN[21].vect_u32);
        state[11].vect_u32 = vzip2q_u32(IN[22].vect_u32,IN[23].vect_u32);
        state[12].vect_u32 = vzip2q_u32(IN[24].vect_u32,IN[25].vect_u32);
        state[13].vect_u32 = vzip2q_u32(IN[26].vect_u32,IN[27].vect_u32);
        state[14].vect_u32 = vzip2q_u32(IN[28].vect_u32,IN[29].vect_u32);
        state[15].vect_u32 = vzip2q_u32(IN[30].vect_u32,IN[31].vect_u32);
        
        OUT[16].vect_u64 = vzip1q_u64(state[0].vect_u64,state[1].vect_u64);//hi32再lo64取出a3
        OUT[17].vect_u64 = vzip1q_u64(state[2].vect_u64,state[3].vect_u64);
        OUT[18].vect_u64 = vzip1q_u64(state[4].vect_u64,state[5].vect_u64);
        OUT[19].vect_u64 = vzip1q_u64(state[6].vect_u64,state[7].vect_u64);
        OUT[20].vect_u64 = vzip1q_u64(state[8].vect_u64,state[9].vect_u64);
        OUT[21].vect_u64 = vzip1q_u64(state[10].vect_u64,state[11].vect_u64);
        OUT[22].vect_u64 = vzip1q_u64(state[12].vect_u64,state[13].vect_u64);
        OUT[23].vect_u64 = vzip1q_u64(state[14].vect_u64,state[15].vect_u64);

        OUT[24].vect_u64 = vzip2q_u64(state[0].vect_u64,state[1].vect_u64);//hi32再hi64取出a4
        OUT[25].vect_u64 = vzip2q_u64(state[2].vect_u64,state[3].vect_u64);
        OUT[26].vect_u64 = vzip2q_u64(state[4].vect_u64,state[5].vect_u64);
        OUT[27].vect_u64 = vzip2q_u64(state[6].vect_u64,state[7].vect_u64);
        OUT[28].vect_u64 = vzip2q_u64(state[8].vect_u64,state[9].vect_u64);
        OUT[29].vect_u64 = vzip2q_u64(state[10].vect_u64,state[11].vect_u64);
        OUT[30].vect_u64 = vzip2q_u64(state[12].vect_u64,state[13].vect_u64);
        OUT[31].vect_u64 = vzip2q_u64(state[14].vect_u64,state[15].vect_u64);
    
    }

    void BS_RO_NEON_UNPACK(__m128i IN[32], __m128i OUT[32])
    { 
        __m128i state1[8];
        __m128i state2[8];
        //对传入的第一组和第二组（原128bit的第一组32bit和第二组32bit）进行lo32
        state1[0].vect_u32 = vzip1q_u32(IN[0].vect_u32,IN[8].vect_u32);
        state1[1].vect_u32 = vzip1q_u32(IN[1].vect_u32,IN[9].vect_u32);
        state1[2].vect_u32 = vzip1q_u32(IN[2].vect_u32,IN[10].vect_u32);
        state1[3].vect_u32 = vzip1q_u32(IN[3].vect_u32,IN[11].vect_u32);
        state1[4].vect_u32 = vzip1q_u32(IN[4].vect_u32,IN[12].vect_u32);
        state1[5].vect_u32 = vzip1q_u32(IN[5].vect_u32,IN[13].vect_u32);
        state1[6].vect_u32 = vzip1q_u32(IN[6].vect_u32,IN[14].vect_u32);
        state1[7].vect_u32 = vzip1q_u32(IN[7].vect_u32,IN[15].vect_u32);

        //第三组和第四组进行lo32
        state2[0].vect_u32 = vzip1q_u32(IN[16].vect_u32,IN[24].vect_u32);
        state2[1].vect_u32 = vzip1q_u32(IN[17].vect_u32,IN[25].vect_u32);
        state2[2].vect_u32 = vzip1q_u32(IN[18].vect_u32,IN[26].vect_u32);
        state2[3].vect_u32 = vzip1q_u32(IN[19].vect_u32,IN[27].vect_u32);
        state2[4].vect_u32 = vzip1q_u32(IN[20].vect_u32,IN[28].vect_u32);
        state2[5].vect_u32 = vzip1q_u32(IN[21].vect_u32,IN[29].vect_u32);
        state2[6].vect_u32 = vzip1q_u32(IN[22].vect_u32,IN[30].vect_u32);
        state2[7].vect_u32 = vzip1q_u32(IN[23].vect_u32,IN[31].vect_u32);

        //对state1和state2中的结果进行lo64取出a、b、i、j......注意OUT的下标，ab是0，cd是1，ef是2，gh是3，ij是4.......
        OUT[0].vect_u64 = vzip1q_u64(state1[0].vect_u64,state2[0].vect_u64);
        OUT[4].vect_u64 = vzip1q_u64(state1[1].vect_u64,state2[1].vect_u64);
        OUT[8].vect_u64 = vzip1q_u64(state1[2].vect_u64,state2[2].vect_u64);
        OUT[12].vect_u64 = vzip1q_u64(state1[3].vect_u64,state2[3].vect_u64);
        OUT[16].vect_u64 = vzip1q_u64(state1[4].vect_u64,state2[4].vect_u64);
        OUT[20].vect_u64 = vzip1q_u64(state1[5].vect_u64,state2[5].vect_u64);
        OUT[24].vect_u64 = vzip1q_u64(state1[6].vect_u64,state2[6].vect_u64);
        OUT[28].vect_u64 = vzip1q_u64(state1[7].vect_u64,state2[7].vect_u64);

        //对state1和state2中的结果进行hi64取出c、d、k、l......
        OUT[1].vect_u64 = vzip2q_u64(state1[0].vect_u64,state2[0].vect_u64);
        OUT[5].vect_u64 = vzip2q_u64(state1[1].vect_u64,state2[1].vect_u64);
        OUT[9].vect_u64 = vzip2q_u64(state1[2].vect_u64,state2[2].vect_u64);
        OUT[13].vect_u64 = vzip2q_u64(state1[3].vect_u64,state2[3].vect_u64);
        OUT[17].vect_u64 = vzip2q_u64(state1[4].vect_u64,state2[4].vect_u64);
        OUT[21].vect_u64 = vzip2q_u64(state1[5].vect_u64,state2[5].vect_u64);
        OUT[25].vect_u64 = vzip2q_u64(state1[6].vect_u64,state2[6].vect_u64);
        OUT[29].vect_u64 = vzip2q_u64(state1[7].vect_u64,state2[7].vect_u64);
        
        //对传入的第一组和第二组进行hi32
        state1[0].vect_u32 = vzip2q_u32(IN[0].vect_u32,IN[8].vect_u32);
        state1[1].vect_u32 = vzip2q_u32(IN[1].vect_u32,IN[9].vect_u32);
        state1[2].vect_u32 = vzip2q_u32(IN[2].vect_u32,IN[10].vect_u32);
        state1[3].vect_u32 = vzip2q_u32(IN[3].vect_u32,IN[11].vect_u32);
        state1[4].vect_u32 = vzip2q_u32(IN[4].vect_u32,IN[12].vect_u32);
        state1[5].vect_u32 = vzip2q_u32(IN[5].vect_u32,IN[13].vect_u32);
        state1[6].vect_u32 = vzip2q_u32(IN[6].vect_u32,IN[14].vect_u32);
        state1[7].vect_u32 = vzip2q_u32(IN[7].vect_u32,IN[15].vect_u32);

        //对传入的第三组和第四组进行hi3
        state2[0].vect_u32 = vzip2q_u32(IN[16].vect_u32,IN[24].vect_u32);
        state2[1].vect_u32 = vzip2q_u32(IN[17].vect_u32,IN[25].vect_u32);
        state2[2].vect_u32 = vzip2q_u32(IN[18].vect_u32,IN[26].vect_u32);
        state2[3].vect_u32 = vzip2q_u32(IN[19].vect_u32,IN[27].vect_u32);
        state2[4].vect_u32 = vzip2q_u32(IN[20].vect_u32,IN[28].vect_u32);
        state2[5].vect_u32 = vzip2q_u32(IN[21].vect_u32,IN[29].vect_u32);
        state2[6].vect_u32 = vzip2q_u32(IN[22].vect_u32,IN[30].vect_u32);
        state2[7].vect_u32 = vzip2q_u32(IN[23].vect_u32,IN[31].vect_u32);
        
        //对state1和state2中的结果进行lo64取出e、f、m、n......
        OUT[2].vect_u64 = vzip1q_u64(state1[0].vect_u64,state2[0].vect_u64);
        OUT[6].vect_u64 = vzip1q_u64(state1[1].vect_u64,state2[1].vect_u64);
        OUT[10].vect_u64 = vzip1q_u64(state1[2].vect_u64,state2[2].vect_u64);
        OUT[14].vect_u64 = vzip1q_u64(state1[3].vect_u64,state2[3].vect_u64);
        OUT[18].vect_u64 = vzip1q_u64(state1[4].vect_u64,state2[4].vect_u64);
        OUT[22].vect_u64 = vzip1q_u64(state1[5].vect_u64,state2[5].vect_u64);
        OUT[26].vect_u64 = vzip1q_u64(state1[6].vect_u64,state2[6].vect_u64);
        OUT[30].vect_u64 = vzip1q_u64(state1[7].vect_u64,state2[7].vect_u64);

        //对state1和state2中的结果进行hi64取出g、h、o、p......
        OUT[3].vect_u64 = vzip2q_u64(state1[0].vect_u64,state2[0].vect_u64);
        OUT[7].vect_u64 = vzip2q_u64(state1[1].vect_u64,state2[1].vect_u64);
        OUT[11].vect_u64 = vzip2q_u64(state1[2].vect_u64,state2[2].vect_u64);
        OUT[15].vect_u64 = vzip2q_u64(state1[3].vect_u64,state2[3].vect_u64);
        OUT[19].vect_u64 = vzip2q_u64(state1[4].vect_u64,state2[4].vect_u64);
        OUT[23].vect_u64 = vzip2q_u64(state1[5].vect_u64,state2[5].vect_u64);
        OUT[27].vect_u64 = vzip2q_u64(state1[6].vect_u64,state2[6].vect_u64);
        OUT[31].vect_u64 = vzip2q_u64(state1[7].vect_u64,state2[7].vect_u64);
    }

    void BS_RO_NEON_TRANS(__m128i IN[32], __m128i OUT[32])
    {   
        __m128i temp1, temp2, M;
        uint8_t k = 0;
        uint8_t r = 0;
        uint64_t m[3][2]={
            {0x5555555555555555,0x5555555555555555},
            {0x3333333333333333,0x3333333333333333},
            {0x0f0f0f0f0f0f0f0f,0x0f0f0f0f0f0f0f0f}
        };//0x55 = 01010101 0x33 = 00110011 0x0f = 00001111

        for (int round = 0; round < 4; round++)
        {   
            for (int j = 0; j < 3; j++)
            {
                k = 1 << j;
                for (int i = 0; i < 8; i++)
                {
                    r = ((i - i % k) << 1) + (i % k);
                    if (r + k > 7) break;
                    M.vect_u64 = vld1q_u64(m[j]);
                    temp1.vect_u32 =  IN[round * 8 + r + k].vect_u32 & shiftLeft(M,k).vect_u32;
                    temp2.vect_u32 = (IN[round * 8 + r].vect_u32 & shiftLeft(M,k).vect_u32) ^ shiftRight(temp1,k).vect_u32;  
                    temp1.vect_u32 = IN[round * 8 + r].vect_u32 & M.vect_u32;
                    IN[round * 8 + r + k].vect_u32 = shiftLeft(temp1,k).vect_u32 ^ (IN[round * 8 + r + k].vect_u32 & M.vect_u32);
                    IN[round * 8 + r] = temp2;
                }
            }
            for (int i = 0; i < 8; i++)
            {
                OUT[round * 8 + i] = IN[round * 8 + i];
            }
        }
    }


    void sm4_bsro_neon_enc(__m128i IN[32],__m128i OUT[32],__m128i rk[32][8])
    {
        __m128i state[32];
        BS_RO_NEON_PACK(IN,state);//数据打包
        // printf("\nafter-pack:\n");
        // dump_hex(state,2048);
        BS_RO_NEON_TRANS(state,IN);//数据转置
        // printf("\nafter-tran:\n");
        // dump_hex(IN,2048);
        BSRO_NEON_iteration(IN,rk);
        // printf("\nafter-sbox:\n");
        // dump_hex(IN,1024);
        BS_RO_NEON_TRANS(IN,state);//数据逆转置
        // printf("\nstate:\n");
        // dump_hex(state,2048);
        BS_RO_NEON_UNPACK(state,OUT);//数据逆打包
        // printf("\nout:\n");
        // dump_hex(OUT,1024);
    }

    void sm4_bsro_neon_ecb_encrypt(uint8_t* outputb, uint8_t* inputb, int size, uint8_t rk[32][8][16]){
        __m128i output_space[32];
        __m128i input_space[32];
        __m128i round_key[32][8];
        memset(outputb,0,size);
        uint8_t* out = outputb;
        uint8_t* in = inputb;

        for (size_t i = 0; i < 32; i++)
        {
            for (size_t j = 0; j < 8; j++)
            {
                round_key[i][j].vect_u8 = vld1q_u8(rk[i][j]);
            }
        }
        
        while(size > 0)
        {
            if(size < 512)
            {
                memset(input_space,0,512);
                int num = size / 16;
                for (size_t i = 0; i < num; i++)
                {
                    input_space[i].vect_u8 = vld1q_u8(in + i * 16);
                }
                
                sm4_bsro_neon_enc(input_space,output_space,round_key);
            
                uint8_t *outputp = (uint8_t*)output_space;
                memcpy(out,outputp,size);

                size = 0;
            
            }
            else
            {
                memset(input_space,0,512);

                for (size_t i = 0; i < 32; i++)
                {
                    input_space[i].vect_u8 = vld1q_u8(in + i * 16);
                }
                
                sm4_bsro_neon_enc(input_space,output_space,round_key);

                uint8_t *outputp = (uint8_t*)output_space;
                memcpy(out,outputp,512);

                size -= 512;
                out += 512;
                in += 512;
            }
            
        }
    }

    void sm4_bsro_neon_ctr_encrypt(uint8_t * outputb, uint8_t * inputb, int size, uint8_t rk[32][8][16], uint8_t * iv)
    {
        uint8_t ctr[512] = {0};
        __m128i input_space[32];
        __m128i output_space[32];
        __m128i round_key[32][8];
        __m128i iv_copy,tmp;
        __m128i count;
        uint8_t op[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
        __m128i cnt;
        uint8_t *out = outputb;

        count.vect_u32 = vdupq_n_u32(0);
        cnt.vect_u8 = vld1q_u8(op);//todo test uint8
        iv_copy.vect_u8 = vld1q_u8(iv); 
         

        for (size_t i = 0; i < 32; i++)
        {
            for (size_t j = 0; j < 8; j++)
            {
                round_key[i][j].vect_u8 = vld1q_u8(rk[i][j]);
            }
        }

        for(int j=0;size;j++)
        {
            int chunk = MIN(size, 512);
            int blocks = chunk / 16;//分组数

            for (int i = 0; i < blocks; i++)
            {
                tmp.vect_u64 = vaddq_u64(iv_copy.vect_u64,count.vect_u64);
                vst1q_u8(ctr+16*i, tmp.vect_u8);
                count.vect_u64 = vaddq_u64(count.vect_u64,cnt.vect_u64);
            }

            memset(input_space,0,512);
            int num = chunk/16;
            for (size_t i = 0; i < num; i++)
            {
                input_space[i].vect_u8 = vld1q_u8(ctr + 16 * i);
            }
        
            sm4_bsro_neon_enc(input_space,output_space,round_key);

            uint8_t *outputp = (uint8_t*)output_space;
            memcpy(out,outputp,chunk);

            size -= chunk;
            out += chunk;

            for(int i = j*512; i < chunk+j*512; i++)
            {
                outputb[i] ^= inputb[i];
            }

        }
    }

    void sm4_bsro_neon_gcm_encrypt(uint8_t *outputb, uint8_t *inputb, int size,
        uint8_t rk[32][8][16], uint8_t *iv, int iv_len, uint8_t *add ,int add_len,
        uint8_t *tag, int tag_len, gcm_context *ctx)
    {
        uint8_t ctr[512] = {0};
        __m128i input_space[32];
        __m128i output_space[32];
        __m128i round_key[32][8];
        __m128i iv_copy,tmp;
        __m128i count;
        uint8_t op[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
        __m128i cnt;
        int length = size;
        uint8_t *out = outputb;

        count.vect_u32 = vdupq_n_u32(0);
        cnt.vect_u8 = vld1q_u8(op);
        iv_copy.vect_u8 = vld1q_u8(iv); 

        for (size_t i = 0; i < 32; i++)
        {
            for (size_t j = 0; j < 8; j++)
            {
                round_key[i][j].vect_u8 = vld1q_u8(rk[i][j]);
            }
        }

        for(int j = 0; size; ++j)
        {
            int chunk = MIN(size, 512);
            int blocks = chunk / 16;

            count.vect_u64 = vaddq_u64(count.vect_u64,cnt.vect_u64);
            
            for (int i = 0; i < blocks; i++)//gcm mode need more 1 block
            {
                //gcm mode iv from 0x02!
                count.vect_u64 = vaddq_u64(count.vect_u64,cnt.vect_u64);
                tmp.vect_u64 = vaddq_u64(iv_copy.vect_u64,count.vect_u64);
                vst1q_u8(ctr+16*i, tmp.vect_u8);
            }

            memset(input_space,0,512);
            
            for (size_t i = 0; i < blocks; i++)
            {
                input_space[i].vect_u8 = vld1q_u8(ctr + i * 16);
            }

            //bs_cipher(ctr, rk);
            sm4_bsro_neon_enc(input_space,output_space,round_key);

            uint8_t *outputp = (uint8_t*)output_space;
            memcpy(out,outputp,chunk);

            size -= chunk;
            out += chunk;

            for(int i = j*512; i < chunk+j*512; i++)
            {
                outputb[i] ^= inputb[i];
            }
        }
        
        //Auth tag test
        //compute tag
        ghash(ctx->T, add,add_len, outputb, length, ctx->buff);
        //uint8_t *ency1 = (uint8_t *) ctr + 16;
        for (int i = 0; i < tag_len; i++)
        {
            tag[i] = ctx->buff[i] ^ ctx->Enc_y0[i];
        }


    }

    void sm4_bsro_neon_key_schedule(uint8_t* key, uint8_t BS_RK[32][8][16])
    {
        uint32_t rkey[32];
        // System parameter or family key
        const uint32_t FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };

        const uint32_t CK[32] = {
        0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
        0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
        0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
        0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
        0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
        0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
        0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
        0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
        };

        uint32_t K[36];
        uint32_t MK[4];
        GET_ULONG_BE( MK[0], key, 0 );
        GET_ULONG_BE( MK[1], key, 4 );
        GET_ULONG_BE( MK[2], key, 8 );
        GET_ULONG_BE( MK[3], key, 12 );

        K[0] = MK[0] ^ FK[0];
        K[1] = MK[1] ^ FK[1];
        K[2] = MK[2] ^ FK[2];
        K[3] = MK[3] ^ FK[3];

        for(int i = 0; i<32; i++)
        {
            K[i+4] = K[i] ^ (sm4CalciRK(K[i+1]^K[i+2]^K[i+3]^CK[i]));
            rkey[i] = K[i+4];
            //printf("rkey[%d]=%08x\n",i,rkey[i]);
        }

        for(int i = 0; i < 32; i++)//rkey的循环
        { 
            uint32_t t = 0x80000000;
            for(int j = 0; j < 32; j++)//rkey[i]的位的循环
            {   
                int tmp = j/8;//j/8向下取整，因为同一512位的寄存器中，每32bit是一样的，所以同时放在0，4，8，12，16，20，24，28...60的uint8_t中的
                if(rkey[i] & t)
                {   
                    BS_RK[i][j%8][0+tmp] = ~0;
                    BS_RK[i][j%8][4+tmp] = ~0;
                    BS_RK[i][j%8][8+tmp] = ~0;
                    BS_RK[i][j%8][12+tmp] = ~0;
                }
                else
                {
                    BS_RK[i][j%8][0+tmp] = 0;
                    BS_RK[i][j%8][4+tmp] = 0;
                    BS_RK[i][j%8][8+tmp] = 0;
                    BS_RK[i][j%8][12+tmp] = 0;
                }
                
                t = t >> 1;
            }
        }
    }

    void sm4_bsro_neon_gcm_init(gcm_context *context, unsigned char *key,
    uint8_t BS_RK[32][8][16], unsigned char *iv)
    {
        //key_schedule
        sm4_bsro_neon_key_schedule(key,BS_RK);
        //compute table, init h and E(y0)

        uint8_t p_h[32],c_h[32];
        memset(p_h, 0, 32);//all 0
        memcpy(p_h+16, iv, 16);//iv||counter0
        memset(p_h+31, 1, 1);
        sm4_bsro_neon_ecb_encrypt(c_h,p_h,32,BS_RK);
        computeTable(context->T, c_h);
        memcpy(context->H, c_h, 16);
        memcpy(context->Enc_y0, c_h+16, 16);
    }

    void BSRO_NEON_iteration(__m128i IN[32], __m128i BS_RK[32][8])
    {
        uint64_t t1 , t2;
        __m128i tmp;
        __m128i ymm[8];
        //四轮放在一起执行，减少32位移位操作
        for (int i = 0; i < 32; i+=4)
        {
            for (int j = 0; j < 8; j++)//32位异或操作
            {
                ymm[j].vect_u32 = IN[8+j].vect_u32 ^ IN[16+j].vect_u32 ^ IN[24+j].vect_u32 ^ BS_RK[i][j].vect_u32;
            }
            
            Sbox_BSRO_NEON(ymm);//正确
        
            L_tran_neon(ymm);

            for (int j = 0; j < 8; j++)//32位异或操作
            {
                IN[j].vect_u32 = ymm[j].vect_u32 ^ IN[j].vect_u32;
            }

            for (int j = 0; j < 8; j++)//32位异或操作
            {
                ymm[j].vect_u32 = IN[j].vect_u32 ^ IN[16+j].vect_u32 ^ IN[24+j].vect_u32 ^ BS_RK[i+1][j].vect_u32;
            }
            
            Sbox_BSRO_NEON(ymm);//正确
        
            L_tran_neon(ymm);
            
            for (int j = 0; j < 8; j++)//32位异或操作
            {
                IN[j+8].vect_u32 = ymm[j].vect_u32 ^ IN[j+8].vect_u32;
            }

            for (int j = 0; j < 8; j++)//32位异或操作
            {
                ymm[j].vect_u32 = IN[j].vect_u32 ^ IN[8+j].vect_u32 ^ IN[24+j].vect_u32 ^ BS_RK[i+2][j].vect_u32;
                //print_m256i(rk);
            }
            
            Sbox_BSRO_NEON(ymm);//正确
        
            L_tran_neon(ymm);
            
            for (int j = 0; j < 8; j++)//32位异或操作
            {
                IN[j+16].vect_u32 = ymm[j].vect_u32 ^ IN[j+16].vect_u32;
            }

            for (int j = 0; j < 8; j++)//32位异或操作
            {
                ymm[j].vect_u32 = IN[j].vect_u32 ^ IN[8+j].vect_u32 ^ IN[16+j].vect_u32 ^ BS_RK[i+3][j].vect_u32;
                //print_m256i(rk);
            }
            
            Sbox_BSRO_NEON(ymm);//正确
        
            L_tran_neon(ymm);
            
            for (int j = 0; j < 8; j++)//32位异或操作
            {
                IN[j+24].vect_u32 = ymm[j].vect_u32 ^ IN[j+24].vect_u32;
            }

        }
    
        for (int j = 0; j < 8; j++)//反序变换
        {
            tmp = IN[j];
            IN[j] = IN[j+24];
            IN[j+24] = tmp;
            tmp = IN[j+8];
            IN[j+8] = IN[j+16];
            IN[j+16] = tmp;
        }
    }

   
    size_t test_sm4_bsro_neon_gcm_crypt_loop(size_t size){

        size_t count = 0;
        uint8_t rk[32][8][16] = {0};
        gcm_context *ctx = gcm_init();
        sm4_bsro_neon_gcm_init(ctx,test_key,rk,test_iv_enc);
        for (count = 0; run && count < 0xffffffffffffffff; count++)
        {
            sm4_bsro_neon_gcm_encrypt(test_output, test_input, size, rk, test_iv_enc, 16, test_aad, 23, test_tag, 16, test_output);
        }
        return count;
    }

    size_t test_sm4_bsro_neon_ctr_crypt_loop(size_t size){
        size_t count = 0;
        uint8_t rk[32][8][16] = {0};
        sm4_bsro_neon_key_schedule(test_key,rk);
        for (count = 0; run && count < 0xffffffffffffffff; count++)
        {
            sm4_bsro_neon_ctr_encrypt(test_output, test_input, size, rk, test_iv_enc);
        }
        
        return count;
    }

    size_t test_sm4_bsro_neon_ecb_crypt_loop(size_t size){
        size_t count = 0;
        uint8_t rk[32][8][16] = {0};
        sm4_bsro_neon_key_schedule(test_key,rk);
        for (count = 0; run && count < 0xffffffffffffffff; count++)
        {
            sm4_bsro_neon_ecb_encrypt(test_output, test_input, size, rk);
        }
        
        return count;
    }


    void performance_test_sm4_bsro_neon()
    {
        size_t size[6] = {16, 64, 256, 1024, 8192, 16384};
        printf("\nsm4_bsro_neon_ecb:\n");
        performance_test_enc(test_sm4_bsro_neon_ecb_crypt_loop, size, 6, 3);
        printf("\nsm4_bsro_neon_ctr:\n");
        performance_test_enc(test_sm4_bsro_neon_ctr_crypt_loop, size, 6, 3);
        printf("\nsm4_bsro_neon_gcm:\n");
        performance_test_enc(test_sm4_bsro_neon_gcm_crypt_loop, size, 6, 3);
    }

    void benchmark_sm4_bs_ro_neon_ecb_encrypt(uint8_t *plain, uint8_t *cipher,int size,uint8_t rk[32][8][16])
    {
        int turns = 10000;
        clock_t t = clock();
        for(int i=0; i<turns; i++)
        {
            sm4_bsro_neon_ecb_encrypt(cipher,plain,size,rk);
        }
        clock_t t1 = clock();
        double tt = (double)(t1 - t) / (CLOCKS_PER_SEC*turns);
        double speed = (double) size / (1024 * 1024 * tt);
        // dump_hex(cipher,size);
        printf("BSRO_NEON_SM4_ECB_encrypt>>> blocks: %d, time: %f s, speed: %f Mb/s\n", size/16, tt, speed*8);
    }

    void benchmark_sm4_bs_ro_neon_ctr_encrypt(uint8_t *plain, uint8_t *cipher,int size,uint8_t rk[32][8][16],uint8_t * iv)
    {
        int turns = 10000;
        clock_t t = clock();
        for(int i=0; i<turns; i++)
        {
            sm4_bsro_neon_ctr_encrypt(cipher,plain,size,rk,iv);
        }
        clock_t t1 = clock();
        double tt = (double)(t1 - t) / (CLOCKS_PER_SEC*turns);
        double speed = (double) size / (1024 * 1024 * tt);
        // dump_hex(cipher,size);
        printf("BSRO_NEON_SM4_CTR_encrypt>>> blocks: %d, time: %f s, speed: %f Mb/s\n", size/16, tt, speed*8);
    }
    void benchmark_sm4_bs_ro_neon_gcm_encrypt(uint8_t *plain, uint8_t *cipher,int size,uint8_t rk[32][8][16],
        uint8_t * iv, int iv_len, uint8_t *add ,int add_len,
        uint8_t *tag, int tag_len, uint8_t T[][256][16])
    {
        int turns = 10000;
        clock_t t = clock();
        for(int i=0; i<turns; i++)
        {
            sm4_bsro_neon_gcm_encrypt(cipher,plain,size,rk,iv,iv_len,add,add_len,
                tag,tag_len,T);
        }
        double tt = (double)(clock() - t) / (CLOCKS_PER_SEC*turns);
        double speed = (double) size / (1024 * 1024 * tt);
        // dump_hex(cipher,size);
        printf("BSRO_NEON_SM4_GCM_encrypt>>> blocks: %d, time: %f s, speed: %f Mb/s\n", size/16, tt, speed*8);
    }

#endif


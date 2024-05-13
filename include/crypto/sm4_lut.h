/*
 * @Author: RyanCLQ
 * @Date: 2023-05-28 12:45:52
 * @LastEditors: RyanCLQ
 * @LastEditTime: 2023-06-09 22:20:50
 * @Description: 请填写简介
 */
/**
 * \file sm4_lut.h
 *
 * \brief This file contains the SM4_LUT algorithm definitions and functions.
 *
 */
#ifndef WBCRYPTO_SM4_LUT_H
#define WBCRYPTO_SM4_LUT_H


#if !defined(WBCRYPTO_CONFIG_FILE)
#include "crypto/config.h"
#else
#include WBCRYPTO_CONFIG_FILE
#endif

#include <stdint.h>
#include <stdlib.h>
#include "crypto/modes.h"
#include "crypto/speed.h"

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * \brief           The SM4 key context structure
     */
    typedef struct wbcrypto_sm4_lut_context
    { 
        uint32_t rk[32];           /*!<  SM4 subkeys       */
    }
    wbcrypto_sm4_lut_context;

    typedef struct wbcrypto_sm4_lut_context WBCRYPTO_SM4_LUT_KEY;


    void wbcrypto_sm4_lut_setkey_enc(wbcrypto_sm4_lut_context *ctx, const unsigned char *user_key);

    void wbcrypto_sm4_lut_setkey_dec(wbcrypto_sm4_lut_context *ctx, const unsigned char *user_key);

    void wbcrypto_sm4_lut_encrypt(const unsigned char *in, unsigned char *out, const wbcrypto_sm4_lut_context *ctx);

    void wbcrypto_sm4_lut_decrypt(const unsigned char *in, unsigned char *out, const wbcrypto_sm4_lut_context *ctx);

    int wbcrypto_sm4_lut_ecb_encrypt(const wbcrypto_sm4_lut_context *ctx, const unsigned char *input, 
                                    size_t ilen, unsigned char *output);

    int wbcrypto_sm4_lut_cbc_encrypt(const wbcrypto_sm4_lut_context *ctx, unsigned char *iv, const unsigned char *input,
                                    size_t ilen, unsigned char *output);

    int wbcrypto_sm4_lut_ctr_encrypt(const wbcrypto_sm4_lut_context *ctx, unsigned char *iv, unsigned char *ecount_buf,
                                    unsigned int *num, const unsigned char *input, size_t ilen, unsigned char *output);

    int wbcrypto_sm4_lut_gcm_encrypt_init(WBCRYPTO_GCM128_CONTEXT *gcm_ctx, wbcrypto_sm4_lut_context *ctx, 
                                        const unsigned char *iv, size_t ivlen, const unsigned char *aad, size_t aadlen);
    
    int wbcrypto_sm4_lut_gcm_encrypt(WBCRYPTO_GCM128_CONTEXT *gcm_ctx, const unsigned char *in, size_t length, unsigned char *out);  

    void wbcrypto_sm4_lut_free(wbcrypto_sm4_lut_context *ctx);  
    
    void performance_test_sm4_lut();
    void sm4_lut_accuracy_test();

    size_t test_sm4_lut_ecb_crypt_loop(size_t size);                          
    size_t test_sm4_lut_cbc_crypt_loop(size_t size); 
    size_t test_sm4_lut_ctr_crypt_loop(size_t size); 
    size_t test_sm4_lut_gcm_crypt_loop(size_t size); 

#ifdef __cplusplus
}
#endif

#endif /* sm4_lut.h */
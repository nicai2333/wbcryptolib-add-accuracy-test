/**
 * \file wbsm4_generator.h
 *
 * \brief This file contains the SM4 whitebox table generate algorithm definitions and functions.
 *
 */
#ifndef  CRYPTRO_WBSM4_GENERATOR_H_
#define  CRYPTRO_WBSM4_GENERATOR_H_

#include <stdint.h>
#include "wbcrypto/wbsm4.h"
#include "crypto/sm4.h"


#if !defined(WBCRYPTO_CONFIG_FILE)
#include "crypto/config.h"
#else
#include WBCRYPTO_CONFIG_FILE
#endif

#ifdef __cplusplus
extern "C" {
#endif



    typedef struct wbcrypto_sm4_context SM4_KEY_CTX;


#if SM4_WHITEBOX_DUMMYROUND_F
   /**
    * \brief              generate sm4 whitebox table context  with dummy round
    *
    * \param key          encrypt or decrypt key
    *
    * \param sm4_wb_ctx   a pointer to an instance of sm4_wb_ctx
    *
    * \param enc          the whitebox SM4 operation: WBCRYPTO_WBSM4_ENCRYPT for encrypt, or WBCRYPTO_WBSM4_DECRYPT for decrypt.
    *
    * \param dummyrounds  add extra dummyrounds.
    *
    * \param randSeed     if input is -1， use the default rand seed, otherwise user customize.
    *
    * \retrun int         \c 0 is successful, otherwise fault.
    */
    int sm4_wb_gen_tables_with_dummyrounds(const uint8_t *key, wbcrypto_wbsm4_context *sm4_wb_ctx, int enc, int dummyrounds, int randSeed);

#endif /* SM4_WHITEBOX_DUMMYROUND_F */




    /**
     * \brief              generate sm4 whitebox encrypt table context with user customized rand seed
     *
     * \param key          encrypt key
     *
     * \param sm4_wb_ctx   a pointer to the whitebox SM4 context to use for encryption.
     *
     * \param enc          the whitebox SM4 operation: WBCRYPTO_WBSM4_ENCRYPT for encrypt, or WBCRYPTO_WBSM4_DECRYPT for decrypt.
     *
     * \param randSeed     if input is -1， use the default rand seed, otherwise user customize.
     *
     * \return             0 is successful, otherwise fault
     */
    int wbcrypto_wbsm4_gentable_enc_with_randseed(wbcrypto_wbsm4_context *sm4_wb_ctx, const unsigned char *key, int randSeed);




    /**
     * \brief              generate sm4 whitebox encrypt table context with user customized rand seed
     *
     * \param key          decrypt key
     *
     * \param sm4_wb_ctx   a pointer to an instance of sm4_wb_ctx
     *
     * \param enc          The whitebox SM4 operation: WBCRYPTO_WBSM4_ENCRYPT for encrypt, or WBCRYPTO_WBSM4_DECRYPT for decrypt.
     *
     * \return int         0 is successful, otherwise fault.
     */
    int wbcrypto_wbsm4_gentable_dec_with_randseed(wbcrypto_wbsm4_context *sm4_wb_ctx, const unsigned char *key, int randSeed);


    /**
     * \brief              generate sm4 whitebox encrypt table and store it to the bytes
     *
     * \param ptr          the pointer to the start of the output buffer.
     *
     * \param key          encrypt key
     *
     * \param randSeed     if input is -1, use the default rand seed, otherwise user customize
     *
     * \param table_size   a pointer to the whitebox table size.
     *
     * \retrun int          0 is successful, otherwise fault
     */
    int wbcrypto_wbsm4_gentable_enc_to_bit(unsigned char *ptr, const unsigned char *key, int randSeed, size_t *table_size);


    /**
     * \brief              generate sm4 whitebox decrypt table and store it to the bytes
     *
     * \param ptr          the pointer to the start of the output buffer.
     *
     * \param key          decrypt key
     *
     * \param randSeed     if input is -1, use the default rand seed, otherwise user customize.
     *
     * \param table_size   a pointer to the whitebox table size.
     *
     * \retrun int          0 is successful, otherwise fault
     */
    int wbcrypto_wbsm4_gentable_dec_to_bit(unsigned char *ptr, const unsigned char *key, int randSeed, size_t *table_size);

    int wbcrypto_wbsm4_gentable_enc(wbcrypto_wbsm4_context *sm4_wb_ctx, const unsigned char *key);
    int wbcrypto_wbsm4_gentable_dec(wbcrypto_wbsm4_context *sm4_wb_ctx, const unsigned char *key);

#endif /* SM4_WHITEBOX_F */

#ifdef __cplusplus
}
#endif

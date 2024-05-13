/**
 * \file wbsm4.h
 *
 * \brief This file contains the SM4 algorithm definitions and functions.
 *
 */

#ifndef  CRYPTRO_WBSM4_H_
#define  CRYPTRO_WBSM4_H_

#include  "crypto/adaptive_error.h"
#include "crypto/modes.h"
#if !defined(WBCRYPTO_CONFIG_FILE)
#include "crypto/config.h"
#else
#include WBCRYPTO_CONFIG_FILE
#endif

#include "wbmatrix/WBMatrix.h"


#define WBCRYPTO_WBSM4_ENCRYPT     1
#define WBCRYPTO_WBSM4_DECRYPT     0

typedef WBCRYPTO_GCM128_CONTEXT WBSM4_GCM128_CONTEXT;


#ifdef __cplusplus
extern "C" {
#endif

    /**
     * \brief           The whitebox SM4 context structure.
     *
     * \note            SM4_WHITEBOX_NUM_STATES is in the config.h.
     */
    typedef struct wbcrypto_wbsm4_context{

        uint32_t rounds;
        uint32_t    ssbox_enc[SM4_WHITEBOX_NUM_STATES][4][256];
        Aff32 M[SM4_WHITEBOX_NUM_STATES][3];
        Aff32 C[SM4_WHITEBOX_NUM_STATES];
        Aff32 D[SM4_WHITEBOX_NUM_STATES];
        Aff32 SE[4];
        Aff32 FE[4];

    } wbcrypto_wbsm4_context;



    /**
     * \brief           Run whitebox SM4 encryption algorithm.
     *
     * \param in        plaintext
     *
     * \param out       cipher
     *
     * \param ctx       A pointer to the whitebox SM4 context to use for encryption or decryption.
     *
     */
    void wbcrypto_wbsm4_encrypt(const unsigned char *in, unsigned char *out, const wbcrypto_wbsm4_context *ctx);


    /**
     * \brief           Run whitebox SM4 decryption algorithm.
     *
     * \param in        cipher
     *
     * \param out       plaintext
     *
     * \param ctx       A pointer to the whitebox SM4 context to use for encryption or decryption.
     *
     */
    void wbcrypto_wbsm4_decrypt(const unsigned char *in, unsigned char *out, const wbcrypto_wbsm4_context *ctx);


    /**
     * \brief          This function performs the whitebox SM4 single-block encryption or decryption operation.
     *
     * \param ctx      A pointer to the whitebox SM4 context to use for encryption or decryption.
     *
     * \param mode     The whitebox SM4 operation: WBCRYPTO_WBSM4_ENCRYPT for encrypt, or WBCRYPTO_WBSM4_DECRYPT for decrypt.
     *
     * \param input    The buffer holding the input data,
     *                 It must be readable and at least 16 Bytes long.
     *
     * \param output   The buffer where the output data will be written,
     *                 It must be writeable and at least 16 Bytes long.
     *
     */
    int wbcrypto_wbsm4_crypt_ecb(const wbcrypto_wbsm4_context *ctx,
                           int mode,
                           const unsigned char *input,
                           unsigned char *output);


    /**
     * \brief           Run whitebox SM4-ECB encryption algorithm.
     *
     * \param ctx       A pointer to the whitebox SM4 context to use for encryption.
     *
     * \param input     plaintext
     *
     * \param ouput     cipher
     *
     */
    int wbcrypto_wbsm4_ecb_encrypt(const wbcrypto_wbsm4_context *ctx,
            const unsigned  char *input, unsigned char *output);




    /**
     * \brief           Run whitebox SM4-ECB decryption algorithm.
     *
     * \param ctx       A pointer to the whitebox SM4 context to use for decryption.
     *
     * \param input     cipher
     *
     * \param ouput     plaintext
     *
     */
    int wbcrypto_wbsm4_ecb_decrypt(const wbcrypto_wbsm4_context *ctx,
                                   const unsigned  char *input, unsigned char *output);



    /**
     * \brief          This function performs the whitebox SM4-CBC encryption or decryption operation on full blocks.
     *
     * \param ctx      A pointer to the whitebox SM4 context to use for encryption or decryption.
     *
     * \param mode     The whitebox SM4 operation: WBCRYPTO_SM4_ENCRYPT for encrypt, or WBCRYPTO_SM4_DECRYPT for decrypt.
     *
     * \param length   The length of the input data in Bytes.
     *
     * \param iv       Initialization vector,
     *                 It must be a readable buffer of \c 16 Bytes.
     *
     * \param input    The buffer holding the input data.
     *                 It must be readable and of size \p length Bytes.
     *
     * \apram output   The buffer holding the output data.
     *                 It must be writeable and of size \p length Bytes.
     *
     * \return         \c 0 on success, otherwise error.
     *
     * \note           According to DRM rules, the last part under 16 bytes will not be encrypted.
     */
    int wbcrypto_wbsm4_crypt_cbc(const wbcrypto_wbsm4_context *ctx,
                           int mode,
                           size_t length,
                           unsigned char *iv,
                           const unsigned char *input,
                           unsigned char *output);


    /**
     * \brief          This function performs the whitebox SM4-CBC encryption with specified IV.
     *
     * \param ctx      A pointer to the whitebox SM4 context to use for encryption.
     *
     * \param length   The length of the input data in Bytes.
     *
     * \param input    The buffer holding the input data.
     *                 It must be readable and of size \p length Bytes.
     *
     * \apram output   The buffer holding the output data.
     *                 It must be writeable and of size \p length Bytes.
     *
     * \return         \c 0 on success, otherwise error.
     *
     * \note           Initialization vector(IV) is specified in "0123456789abcedf".
     *                 According to DRM rules, the last part under 16 bytes will not be encrypted.
     */
     int wbcrypto_wbsm4_cbc_encrypt(const wbcrypto_wbsm4_context *ctx,
                                    size_t length,
                                    unsigned char *input,
                                    unsigned char *output);



    /**
     * \brief          This function performs the whitebox SM4-CBC decryption with specified IV.
     *
     * \param ctx      A pointer to the whitebox SM4 context to use for decryption.
     *
     * \param length   The length of the input data in Bytes.
     *
     * \param input    The buffer holding the input data.
     *                 It must be readable and of size \p length Bytes.
     *
     * \apram output   The buffer holding the output data.
     *                 It must be writeable and of size \p length Bytes.
     *
     * \return         \c 0 on success, otherwise error.
     *
     * \note           Initialization vector(IV) is specified in "0123456789abcedf".
     *                 According to DRM rules, the last part under 16 bytes will not be decrypted.
     */
    int wbcrypto_wbsm4_cbc_decrypt(const wbcrypto_wbsm4_context *ctx,
                                   size_t length,
                                   unsigned char *input,
                                   unsigned char *output);




    /**
     * \brief            This function performs the whitebox SM4-GCM encryption or decryption operation on full blocks.
     *
     * \param ctx        A pointer to the whitebox SM4 context to use for encryption or decryption.
     *
     * \param mode       The whitebox SM4 operation: WBCRYPTO_SM4_ENCRYPT for encrypt, or #WBCRYPTO_SM4_DECRYPT for decrypt.
     *
     * \param length     The length of the input data in Bytes.
     *
     * \param iv         Initialization vector,
     *                   It must be a readable buffer of \p iv_length Bytes.
     *
     * \param iv_length  The length of \p iv in Bytes.
     *
     *  \param aad       Additional authenticated data,
     *                   It must be a readable buffer of \p aad_length Bytes.
     *
     * \param aad_length The length of \p aad in Bytes.
     *
     * \param input      The buffer holding the input data.
     *                   It must be readable and of size \p length Bytes.
     *
     * \apram output     The buffer holding the output data.
     *                   It must be writeable and of size \p length Bytes.
     *
     * \return           \c 0 on success, otherwise error.
     *
     * \note             According to DRM rules, the last part under 16 bytes will not be decrypted.
     */
    int wbcrypto_wbsm4_crypt_gcm(wbcrypto_wbsm4_context *ctx,
                                 int mode,size_t length,
                                 unsigned char *iv, size_t iv_length,
                                 unsigned char *aad, size_t aad_length,
                                 const unsigned char *input,
                                 unsigned char *output);



    /**
     * \brief          This function performs the SM4-GCM encryption with specified IV and AAD.
     *
     * \param ctx      A pointer to the whitebox SM4 context to use for encryption or decryption.
     *
     * \param length   The length of the input data in Bytes.
     *
     * \param input    The buffer holding the input data.
     *                 It must be readable.
     *
     * \apram output   The buffer holding the output data.
     *                 It must be writeable.
     *
     * \return         \c 0 on success, otherwise error.
     *
     * \note           Initialization vector(IV) is specified in "0123456789abcedf".
     *                 Additional authenticated data is specified in "0123456789abcdef".
     *                 According to DRM rules, the last part under 16 bytes is not encrypted.
     */
    int wbcrypto_wbsm4_gcm_encrypt(wbcrypto_wbsm4_context *ctx,
                                    size_t length,
                                    const unsigned char *input,
                                    unsigned char *output);





    /**
     * \brief          This function performs the SM4-GCM decryption with specified IV and AAD.
     *
     * \param ctx      A pointer to the whitebox SM4 context to use for decryption.
     *
     * \param length   The length of the input data in Bytes.
     *
     * \param input    The buffer holding the input data.
     *                 It must be readable.
     *
     * \apram output   The buffer holding the output data.
     *                 It must be writeable.
     *
     * \return         \c 0 on success, otherwise error.
     *
     * \note           Initialization vector(IV) is specified in "0123456789abcedf".
     *                 Additional authenticated data is specified in "0123456789abcdef".
     *                 According to DRM rules, the last part under 16 bytes is not encrypted.
     */
    int wbcrypto_wbsm4_gcm_decrypt(wbcrypto_wbsm4_context *ctx,
                                   size_t length,
                                   const unsigned char *input,
                                   unsigned char *output);



    /**
     * \brief          This function performs an whitebox SM4 context to bit strings.
     *
     * \param ctx      A pointer to the whitebox SM4 context to use for encryption.
     *
     * \param dest     The address of the pointer to the start of the output buffer.
     *
     * \return         whitebox SM4 table size in Bytes.
     */
    int wbcrypto_wbsm4_export_to_str(const wbcrypto_wbsm4_context* ctx,
                             void **dest);



    /**
     * \brief          This function transform the bit strings to whitebox SM4 context.
     *
     * \param source   The pointer of the input buffer.
     *
     * \return         whitebox SM4 context.
    */
    wbcrypto_wbsm4_context* wbcrypto_wbsm4_import_from_str(const void *source);



    void wbcrypto_wbsm4_gcm128_init( WBSM4_GCM128_CONTEXT *gcm_ctx, wbcrypto_wbsm4_context *wb_ctx);



    void wbcrypto_wbsm4_gcm128_setiv( WBSM4_GCM128_CONTEXT *gcm_ctx, const unsigned char *ivec, size_t len);



    int wbcrypto_wbsm4_gcm128_aad( WBSM4_GCM128_CONTEXT *gcm_ctx, const unsigned char *aad, size_t len);



    int wbcrypto_wbsm4_gcm128_encrypt(const unsigned char *in, unsigned char *out,
                                      size_t length,  WBSM4_GCM128_CONTEXT *gcm_ctx, const int mode);

    #ifdef __cplusplus
    }
    #endif
    void wbcrypto_wbsm4_gcm128_tag(WBSM4_GCM128_CONTEXT *gcm_ctx, unsigned char *tag,
                       size_t len); 

#endif
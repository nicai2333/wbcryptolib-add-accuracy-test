/**
 *
 * \file keybox_wbsm2.h
 *
 * \brief This file contains the KeyBox encrypted storage service for White Box SM2 algorithm
 *
 */
#ifndef WBCRYPTO_KEYBOX_WBSM2_H_
#define WBCRYPTO_KEYBOX_WBSM2_H_

#if !defined(WBCRYPTO_CONFIG_FILE)
#include "crypto/config.h"
#else
#include WBCRYPTO_CONFIG_FILE
#endif

#include  "crypto/adaptive_error.h"
#include "stdint.h"
#include "wbcrypto/wbsm2.h"


#define WBCRYPTO_ERR_KEYBOX_GENERIC_FAILURE                    WBCRYPTO_ADAPT_ERROR(-0x0A00)  /**< Unknown failure in this function. **/
#define WBCRYPTO_ERR_KEYBOX_ALLOC_FAILED                       WBCRYPTO_ADAPT_ERROR(-0x0A01)  /**< Failed to allocate memory. */
#define WBCRYPTO_ERR_KEYBOX_SETUP_FAILED                       WBCRYPTO_ADAPT_ERROR(-0x0A02)  /**< Failed to run setup function to a data struct */
#define WBCRYPTO_ERR_KEYBOX_BAD_INPUT_DATA                     WBCRYPTO_ADAPT_ERROR(-0x0A03)  /**< Bad input parameters to function, usually hints programming error */
#define WBCRYPTO_ERR_KEYBOX_MALFORMED_KEYBOX                   WBCRYPTO_ADAPT_ERROR(-0x0A04)  /**< Bad serialized keybox to function. */
#define WBCRYPTO_ERR_KEYBOX_OUTPUT_TOO_LARGE                   WBCRYPTO_ADAPT_ERROR(-0x0A05)  /**< The output buffer for decryption is not large enough. */
#define WBCRYPTO_ERR_KEYBOX_NO_SUCH_COMPONENT                  WBCRYPTO_ADAPT_ERROR(-0x0A06)  /**< The component to save is not loaded */

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * the bit flag to indicate the components of the keybox, OR them together to specify multiple parts
     */
    typedef enum {
        WBCRYPTO_KEYBOX_WBSM2_PUBLIC_KEY = 0x1,
        WBCRYPTO_KEYBOX_WBSM2_PRIVATE_SEGMENT_A = 0x2,
        WBCRYPTO_KEYBOX_WBSM2_PRIVATE_SEGMENT_B = 0x4,
        WBCRYPTO_KEYBOX_WBSM2_ALL = 0x7
    } wbcrypto_keybox_wbsm2_component;


    /**
     * the White Box SM2 Key Box
     *
     * \note we uses a bit flag to save what components are loaded, so set it up after you set a component manually
     */
    typedef struct {
        wbcrypto_keybox_wbsm2_component loaded;      // the available components bit flag in the keybox, set this up after manually setting a component!
        uint8_t iv[16];                              // IV for encryption
        wbcrypto_wbsm2_public_key pubkey;            // public key of WBSM2
        wbcrypto_wbsm2_private_key_segment segmentA; // private key segmentA of WBSM2
        wbcrypto_wbsm2_private_key_segment segmentB; // private key segmentB of WBSM2
    } wbcrypto_keybox_wbsm2;

    /**
     * initialize the keybox
     *
     * \param ctx the box to init, must not be NULL!
     */
    void wbcrypto_keybox_wbsm2_init(wbcrypto_keybox_wbsm2* ctx);

    /**
     * free the keybox, destroy all components
     *
     * \param ctx the box to free, NULL is a trivial no-op
     */
    void wbcrypto_keybox_wbsm2_free(wbcrypto_keybox_wbsm2* ctx);


    /**
     * read & decrypt the keybox's specified part(by to_load) from the serialized form
     *
     * \param ctx                         the keybox to load into
     *
     * \param key                         the SM4 key used to decrypt, MUST NOT BE NULL
     *
     * \param key_size                    the key's size, it's now 16
     *
     * \param serialized_keybox           buffer to put the serialized form, advised value is at least 512
     *
     * \param serialized_keybox_size      the size of serialized form
     *
     * \param to_load_mask                the mask of component to load, via bit flags
     *
     * \return 0 on success, otherwise error
     * \return WBCRYPTO_ERR_KEYBOX_MALFORMED_KEYBOX if the serialized keybox is malformed(corrupted)
     * \return other error values are possible
     *
     * \note the ctx will hold the IV stored in the serialized keybox after the operation
     *
     * \note the to_load_mask flag is to allow more flexible storage options, you can store 3 components at 1 place, or 3 at all different places,
     *     and load them either one at a time on being used or load all of them in one go
     *
     * \note the to_load_mask flag is permissive,
     *     it means that if the serialized keybox have Only SEGMENT_A and SEGMENT_B and you asked ALL ( PUBKEY | SEGMENT_A | SEGMENT_B )
     *     the PUBKEY will be left in uninitialized state, meaning the loaded field will not set the corresponding bit,
     *     use the ctx->loaded to check out is it really loaded!
     */
    int wbcrypto_keybox_wbsm2_load(
        wbcrypto_keybox_wbsm2* ctx,
        uint8_t* key, size_t key_size,
        uint8_t* serialized_keybox, size_t serialized_keybox_size,
        wbcrypto_keybox_wbsm2_component to_load_mask
    );

    /**
     * encrypt & write the keybox's specified part(by to_save) into serialized form
     *
     * \param ctx                         the keybox
     *
     * \param key                         the SM4 key used to encrypt, MUST NOT BE NULL
     *
     * \param key_size                    the key's size, it's now 16
     *
     * \param serialized_keybox           buffer to put the serialized form, advised value is at least 512
     *
     * \param max_serialized_keybox_size  the size limit of buffer
     *
     * \param serialized_keybox_size      the actual size of serialized form
     *
     * \param to_save                     the component to serialize, via bit flags
     *
     * \return 0 on success, otherwise error
     * \return WBCRYPTO_ERR_KEYBOX_OUTPUT_TOO_LARGE if the serialized_keybox buffer is too small
     * \return WBCRYPTO_ERR_ASN1 family if internal ASN.1 encoding failed
     * \return other error values are possible
     *
     * \note this function gets the IV to encrypt from the keybox, SET IT BEFORE SAVE IT!
     *
     * \note to save a component in the box, it MUST BE LOADED AT FIRST (either by wbcrypto_keybox_wbsm2_load or manually copied in & set the loaded flag)
     *         this is to allow more flexible storage options, so you can either save all in one place, or save all three component into three different places
     */
    int wbcrypto_keybox_wbsm2_save(
        wbcrypto_keybox_wbsm2* ctx,
        uint8_t* key, size_t key_size,
        uint8_t* serialized_keybox, size_t max_serialized_keybox_size, size_t* serialized_keybox_size,
        wbcrypto_keybox_wbsm2_component to_save
    );

#ifdef __cplusplus
}
#endif
	
#endif
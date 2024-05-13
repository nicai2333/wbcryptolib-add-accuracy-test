#ifndef WBCRYPTO_INTERNAL_KEYBOX_WBSM2_ASN1_WRITE_H_
#define WBCRYPTO_INTERNAL_KEYBOX_WBSM2_ASN1_WRITE_H_

#include "wbcrypto/keybox_wbsm2.h"

/**
 * \brief write the EncryptedWBSM2KeyBox
 *
 * \return   The number of bytes written to \p p on success.
 * \return   A negative \c MBEDTLS_ERR_ASN1_XXX error code on ASN.1 failure
 */
int wbcrypto_keybox_wbsm2_asn1_write_keybox(
    uint8_t** p, uint8_t* start,
    uint8_t* iv, size_t iv_size,
    uint8_t* encrypted_keybox, size_t encrypted_keybox_size
);

size_t wbcrypto_keybox_wbsm2_asn1_keybox_buflength(size_t iv_size, size_t encrypted_keybox_size);


/**
 * \brief write the EncryptedWBSM2KeyBox
 *
 * \return   The number of bytes written to \p p on success.
 * \return   A negative \c MBEDTLS_ERR_ASN1_XXX error code on ASN.1 failure
 * \return   other error codes are possible
 */
int wbcrypto_keybox_wbsm2_asn1_write_encrypted_keybox(
    uint8_t** p, uint8_t* start,
    wbcrypto_keybox_wbsm2* ctx,
    wbcrypto_keybox_wbsm2_component to_save
);

size_t wbcrypto_keybox_wbsm2_asn1_encrypted_keybox_buflength(
    wbcrypto_keybox_wbsm2* ctx,
    wbcrypto_keybox_wbsm2_component to_save
);


/**
 * \brief write the SubjectPublicKeyInfo
 *
 * \return   The number of bytes written to \p p on success.
 * \return   A negative \c MBEDTLS_ERR_ASN1_XXX error code on ASN.1 failure
 * \return   other error codes are possible
 */
int wbcrypto_keybox_wbsm2_asn1_write_public_key(
    uint8_t** p, uint8_t* start,
    wbcrypto_wbsm2_public_key* pubkey
);

size_t wbcrypto_keybox_wbsm2_asn1_public_key_buflength(
    wbcrypto_wbsm2_public_key* pubkey
);


/**
 * \brief write the WBSM2SKSegment
 *
 * \return   The number of bytes written to \p p on success.
 * \return   A negative \c MBEDTLS_ERR_ASN1_XXX error code on ASN.1 failure
 * \return   other error codes are possible
 */
int wbcrypto_keybox_wbsm2_asn1_write_private_key_segment(
    uint8_t** p, uint8_t* start,
    int tag,
    wbcrypto_wbsm2_private_key_segment* segment
);

size_t wbcrypto_keybox_wbsm2_asn1_private_key_segment_buflength(
    int tag,
    wbcrypto_wbsm2_private_key_segment* segment
);


/**
* \brief    write the AlgorithmIdentifier for WBSM2 Keybox, we only allow NamedCurve& SM2P256V1 for now, so no param needed
*
* \return   The number of bytes written to \p p on success.
* \return   A negative \c MBEDTLS_ERR_ASN1_XXX error code on failure.
*
**/
int wbcrypto_keybox_wbsm2_asn1_write_algorithm_identifer(
    uint8_t** p, uint8_t* start
);

size_t wbcrypto_keybox_wbsm2_asn1_algorithm_identifer_buflength();


/**
 * \brief write the ECParameter, we only allow SM2P256V1 for now, so no param needed
 * 
 * \return          The number of bytes written to \p p on success.
 * \return          A negative \c MBEDTLS_ERR_ASN1_XXX error code on failure.
 */
int wbcrypto_keybox_wbsm2_asn1_write_ec_parameter(
    uint8_t** p, uint8_t* start
);

size_t wbcrypto_keybox_wbsm2_asn1_ec_parameter_buflength();

#endif
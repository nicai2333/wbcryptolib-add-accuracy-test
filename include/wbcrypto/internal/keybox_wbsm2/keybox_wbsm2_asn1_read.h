#ifndef WBCRYPTO_INTERNAL_KEYBOX_WBSM2_ASN1_READ_H_
#define WBCRYPTO_INTERNAL_KEYBOX_WBSM2_ASN1_READ_H_

#include "wbcrypto/keybox_wbsm2.h"
#include "wbcrypto/internal/asn1_utils.h"


/**
 * \brief   parse the WBSM2KeyBox ASN.1 part
 *
 * \return  0 on success,
 * \return  MBEDTLS_ERR_ASN1 Family on ASN.1 Parsing Error
 */
int wbcrypto_keybox_wbsm2_asn1_parse_keybox(
    uint8_t** p, uint8_t* end,
    wbcrypto_asn1_octetstring* iv,
    wbcrypto_asn1_octetstring* encrypted_keybox
);

/**
 * \brief   parse the EncryptedWBSM2KeyBox ASN.1 part
 *
 * \return  0 on success,
 * \return  MBEDTLS_ERR_ASN1 Family on ASN.1 Parsing Error
 * \return  WBCRYPTO_ERR_KEYBOX_BAD_INPUT_DATA on assertion failure
 * \return  MBEDTLS_ERR_ECP Family on ECP related loading error
 * \return  MBEDTLS_ERR_MPI Family on MPI related loading error
 */
int wbcrypto_keybox_wbsm2_asn1_parse_encrypted_keybox(
    uint8_t** p, uint8_t* end,
    wbcrypto_keybox_wbsm2* ctx,
    wbcrypto_keybox_wbsm2_component to_load
);

/**
 * \brief   parse the SubjectPublicKeyInfo ASN.1 part
 *
 * \return  0 on success,
 * \return  MBEDTLS_ERR_ASN1 Family on ASN.1 Parsing Error
 * \return  WBCRYPTO_ERR_KEYBOX_BAD_INPUT_DATA on algorithm identifier Assertion Failed
 * \return  MBEDTLS_ERR_ECP Family on ECP related loading error
 * \return  MBEDTLS_ERR_MPI Family on MPI related loading error
 */
int wbcrypto_keybox_wbsm2_asn1_parse_public_key(
    uint8_t** p, uint8_t* end,
    wbcrypto_wbsm2_public_key* pubkey
);

/**
 * \brief   parse the WBSM2SKSegment ASN.1 part
 *
 * \return  0 on success,
 * \return  MBEDTLS_ERR_ASN1 Family on ASN.1 Parsing Error
 * \return  WBCRYPTO_ERR_KEYBOX_BAD_INPUT_DATA on grp Assertion Failed
 * \return  MBEDTLS_ERR_ECP Family on ECP related loading error
 * \return  MBEDTLS_ERR_MPI Family on MPI related loading error
 */
int wbcrypto_keybox_wbsm2_asn1_parse_private_key_segment(
    uint8_t** p, uint8_t* end,
    int tag,
    wbcrypto_wbsm2_private_key_segment* segment
);


/**
 * \brief   assert the Algorithm Identifier is correct(unconstrained & NamedCurve-SM2P256V1)
 *
 * \return  0 on success,
 * \return  MBEDTLS_ERR_ASN1 Family on ASN.1 Parsing Error
 * \return  WBCRYPTO_ERR_KEYBOX_BAD_INPUT_DATA on Assertion Failed
 */
int wbcrypto_keybox_wbsm2_asn1_assert_algorithm_identifer(
    uint8_t** p, uint8_t* start
);

/**
 * \brief   assert the ECParameter is NamedCurve with SM2P256V1 as OID
 *
 * \return  0 on success,
 * \return  MBEDTLS_ERR_ASN1 Family on ASN.1 Parsing Error
 * \return  WBCRYPTO_ERR_KEYBOX_BAD_INPUT_DATA on Assertion Failed
 */
int wbcrypto_keybox_wbsm2_asn1_assert_ec_parameter(
    uint8_t** p, uint8_t* start
);

#endif
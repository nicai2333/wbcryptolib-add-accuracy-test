#ifndef WBCRYPTO_INTERNAL_KEYBOX_WBSM2_ASN1_FORMAT_H_
#define WBCRYPTO_INTERNAL_KEYBOX_WBSM2_ASN1_FORMAT_H_

#include "mbedtls/asn1.h"

/**
 *  The format of White Box SM2 KeyBox:
 *
 *  WBSM2KeyBox ::= SEQUENCE {
 *      IV OCTET STRING
 *      keybox OCTET STRING //EncryptedWBSM2KeyBox, encrypted with SM4-CBC
 *  }
 *
 *  EncryptedWBSM2KeyBox ::= SEQUENCE {
 *      pubkey   [0] EXPLICIT SubjectPublicKeyInfo OPTIONAL //see RFC5480
 *      segmentA [1] EXPLICIT WBSM2SKSegment OPTIONAL
 *      segmentB [2] EXPLICIT WBSM2SKSegment OPTIONAL
 * }
 *
 * WBSM2SKSegment ::= SEQUENCE {
 *      grp ECParameters //see RFC5480
 *      W BIT STRING // uncompressed form of Point W
 *      hd INTEGER
 * }
 *
 *
 */

#define WBCRYPTO_OID_SM2 "\x2a\x81\x1c\xcf\x55\x01\x82\x2d"
#define WBCRYPTO_OID_CURVE_SM2P256V1 WBCRYPTO_OID_SM2

#define WBCRYPTO_KEYBOX_WBSM2_ASN1_PUBLIC_KEY_TAG (0x80 | MBEDTLS_ASN1_CONSTRUCTED | 0x00 )
#define WBCRYPTO_KEYBOX_WBSM2_ASN1_PRIVATE_SEGMENT_A_TAG (0x80 | MBEDTLS_ASN1_CONSTRUCTED | 0x01 )
#define WBCRYPTO_KEYBOX_WBSM2_ASN1_PRIVATE_SEGMENT_B_TAG (0x80 | MBEDTLS_ASN1_CONSTRUCTED | 0x02 )


#endif
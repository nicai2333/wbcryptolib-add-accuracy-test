#include <stdlib.h>
#include <string.h>
#include "wbcrypto/wbsm2.h"
#include "wbcrypto/keybox_wbsm2.h"
#include "wbcrypto/sm2coop.h"
#include "mbedtls/asn1.h"
#include "mbedtls/oid.h"
#include "wbcrypto/internal/keybox_wbsm2/keybox_wbsm2_asn1_read.h"
#include "wbcrypto/internal/keybox_wbsm2/keybox_wbsm2_asn1_format.h"
#include "wbcrypto/internal/marco_utils.h"
#include "wbcrypto/internal/asn1_utils.h"


int wbcrypto_keybox_wbsm2_asn1_parse_keybox(
    uint8_t** p, uint8_t* end,
    wbcrypto_asn1_octetstring* iv,
    wbcrypto_asn1_octetstring* encrypted_keybox
) {
    int ret;

    size_t total_size;
    THROW_ONNZ(mbedtls_asn1_get_tag(p, end, &total_size, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    THROW_ONNZ(wbcrypto_asn1_get_octetstring(p, end, iv));
    THROW_ONNZ(wbcrypto_asn1_get_octetstring(p, end, encrypted_keybox));

cleanup:
    return ret;
}

int wbcrypto_keybox_wbsm2_asn1_parse_encrypted_keybox(
    uint8_t** p, uint8_t* end,
    wbcrypto_keybox_wbsm2* ctx,
    wbcrypto_keybox_wbsm2_component to_load
) {
    int ret;

    size_t total_size;
    THROW_ONNZ(mbedtls_asn1_get_tag(p, end, &total_size, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    //after_p must go before end
    uint8_t* after_p = *p + total_size;
    if (after_p > end) {
        THROW(MBEDTLS_ERR_ASN1_OUT_OF_DATA);
    }

    while (to_load != 0 && *p < after_p) {
        const uint8_t tag = **p;
        if (to_load & WBCRYPTO_KEYBOX_WBSM2_PUBLIC_KEY && tag == WBCRYPTO_KEYBOX_WBSM2_ASN1_PUBLIC_KEY_TAG) {
            to_load &= ~(WBCRYPTO_KEYBOX_WBSM2_PUBLIC_KEY);
            THROW_ONNZ(wbcrypto_keybox_wbsm2_asn1_parse_public_key(p, end, &ctx->pubkey));
            ctx->loaded |= WBCRYPTO_KEYBOX_WBSM2_PUBLIC_KEY;
        }
        else if (to_load & WBCRYPTO_KEYBOX_WBSM2_PRIVATE_SEGMENT_A && tag == WBCRYPTO_KEYBOX_WBSM2_ASN1_PRIVATE_SEGMENT_A_TAG) {
            to_load &= ~(WBCRYPTO_KEYBOX_WBSM2_PRIVATE_SEGMENT_A);
            THROW_ONNZ(wbcrypto_keybox_wbsm2_asn1_parse_private_key_segment(p, end, WBCRYPTO_KEYBOX_WBSM2_ASN1_PRIVATE_SEGMENT_A_TAG, &ctx->segmentA));
            ctx->loaded |= WBCRYPTO_KEYBOX_WBSM2_PRIVATE_SEGMENT_A;
        }
        else if (to_load & WBCRYPTO_KEYBOX_WBSM2_PRIVATE_SEGMENT_B && tag == WBCRYPTO_KEYBOX_WBSM2_ASN1_PRIVATE_SEGMENT_B_TAG) {
            to_load &= ~(WBCRYPTO_KEYBOX_WBSM2_PRIVATE_SEGMENT_B);
            THROW_ONNZ(wbcrypto_keybox_wbsm2_asn1_parse_private_key_segment(p, end, WBCRYPTO_KEYBOX_WBSM2_ASN1_PRIVATE_SEGMENT_B_TAG, &ctx->segmentB));
            ctx->loaded |= WBCRYPTO_KEYBOX_WBSM2_PRIVATE_SEGMENT_B;
        } else {
	        //proceed to next
            (*p)++;
            size_t size;
            THROW_ONNZ(mbedtls_asn1_get_len(p, end, &size));
            *p += size;
        }
    }

cleanup:
    return ret;
}

int wbcrypto_keybox_wbsm2_asn1_parse_public_key(
    uint8_t** p, uint8_t* end,
    wbcrypto_wbsm2_public_key* pubkey
) {
    int ret;

    size_t total_size;
    THROW_ONNZ(mbedtls_asn1_get_tag(p, end, &total_size, WBCRYPTO_KEYBOX_WBSM2_ASN1_PUBLIC_KEY_TAG));

    //deal with AlgorithmIdentifier
    THROW_ONNZ(wbcrypto_keybox_wbsm2_asn1_assert_algorithm_identifer(p, end));

    //deal with subjectPublicKey BIT STRING
    mbedtls_asn1_bitstring subjectPK;
    THROW_ONNZ(wbcrypto_asn1_get_bitstring(p, end, &subjectPK));

	//load result
    THROW_ONNZ(wbcrypto_wbsm2_load_default_group(&pubkey->grp));
    THROW_ONNZ(mbedtls_ecp_point_read_binary(&pubkey->grp, &pubkey->P, subjectPK.p, subjectPK.len));

cleanup:
    return ret;
}

int wbcrypto_keybox_wbsm2_asn1_parse_private_key_segment(
    uint8_t** p, uint8_t* end,
    int tag,
    wbcrypto_wbsm2_private_key_segment* segment
) {
    int ret;
    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    THROW_ONNZ(wbcrypto_wbsm2_load_default_group(&grp));
	
    size_t total_size;
    THROW_ONNZ(mbedtls_asn1_get_tag(p, end, &total_size, tag));

    THROW_ONNZ(wbcrypto_keybox_wbsm2_asn1_assert_ec_parameter(p, end));

    mbedtls_asn1_bitstring W_buf;
    THROW_ONNZ(wbcrypto_asn1_get_bitstring(p, end, &W_buf));
    THROW_ONNZ(mbedtls_ecp_point_read_binary(&grp, &segment->W, W_buf.p, W_buf.len));

    THROW_ONNZ(mbedtls_asn1_get_mpi(p, end, &segment->hd));

cleanup:
    mbedtls_ecp_group_free(&grp);
    return ret;
}


int wbcrypto_keybox_wbsm2_asn1_assert_algorithm_identifer(
    uint8_t** p, uint8_t* end
) {
    int ret;

    mbedtls_asn1_buf alg, param;
    THROW_ONNZ(mbedtls_asn1_get_alg(p, end, &alg, &param));

    //assert algorithm according to RFC5480
    if (memcmp(alg.p, MBEDTLS_OID_EC_ALG_UNRESTRICTED, sizeof(MBEDTLS_OID_EC_ALG_UNRESTRICTED) - 1) != 0) {
        THROW(WBCRYPTO_ERR_KEYBOX_BAD_INPUT_DATA);
    }

    //assert param is NamedCurve with sm2p256v1
    if (param.tag != MBEDTLS_ASN1_OID) {
        THROW(WBCRYPTO_ERR_KEYBOX_BAD_INPUT_DATA);
    }
    if (
        param.len != sizeof(WBCRYPTO_OID_CURVE_SM2P256V1) - 1 
        || memcmp(param.p, WBCRYPTO_OID_CURVE_SM2P256V1, sizeof(WBCRYPTO_OID_CURVE_SM2P256V1) - 1) != 0
    ) {
        THROW(WBCRYPTO_ERR_KEYBOX_BAD_INPUT_DATA);
    }

cleanup:
    return ret;
}

int wbcrypto_keybox_wbsm2_asn1_assert_ec_parameter(
    uint8_t** p, uint8_t* end
) {
    int ret;

    wbcrypto_asn1_oid oid;
    THROW_ONNZ(wbcrypto_asn1_get_oid(p, end, &oid));

    //assert param is NamedCurve with sm2p256v1
	if (    
        oid.len != sizeof(WBCRYPTO_OID_CURVE_SM2P256V1) - 1
		|| memcmp(oid.p, WBCRYPTO_OID_CURVE_SM2P256V1, sizeof(WBCRYPTO_OID_CURVE_SM2P256V1) - 1) != 0
    ) {
        THROW(WBCRYPTO_ERR_KEYBOX_BAD_INPUT_DATA);
    }

cleanup:
    return ret;
}
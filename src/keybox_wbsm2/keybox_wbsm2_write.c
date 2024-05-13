#include "wbcrypto/wbsm2.h"
#include "wbcrypto/keybox_wbsm2.h"
#include "crypto/sm4.h"
#include "wbcrypto/sm2coop.h"
#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "wbcrypto/internal/marco_utils.h"
#include "wbcrypto/internal/asn1_utils.h"
#include "wbcrypto/internal/keybox_wbsm2/keybox_wbsm2_asn1_format.h"
#include "wbcrypto/internal/keybox_wbsm2/keybox_wbsm2_asn1_write.h"
#include <stdlib.h>
#include <string.h>
#include "mbedtls/oid.h"
#include "wbcrypto/internal/keybox_wbsm2/keybox_wbsm2_asn1_read.h"


int wbcrypto_keybox_wbsm2_asn1_write_keybox(
    uint8_t** p, uint8_t* start,
    uint8_t* iv, size_t iv_size,
    uint8_t* encrypted_keybox, size_t encrypted_keybox_size
) {
    int ret;

	size_t content_size = 0;
    WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_octet_string(p, start, encrypted_keybox, encrypted_keybox_size));
    content_size += ret;
    WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_octet_string(p, start, iv, iv_size));
    content_size += ret;

    WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_len(p, start, content_size));
    const size_t len_size = ret;
    WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    const size_t tag_size = ret;

    ret = tag_size + len_size + content_size;
cleanup:
    return ret;
}

size_t wbcrypto_keybox_wbsm2_asn1_keybox_buflength(size_t iv_size, size_t encrypted_keybox_size) {
    return WBCRYPTO_ASN1_TAG_BUFLENGTH
        + wbcrypto_asn1_len_buflength(iv_size + encrypted_keybox_size)
        + wbcrypto_asn1_octet_string_buflength(iv_size)
        + wbcrypto_asn1_octet_string_buflength(encrypted_keybox_size)
        ;
}

int wbcrypto_keybox_wbsm2_asn1_write_encrypted_keybox(
    uint8_t** p, uint8_t* start,
    wbcrypto_keybox_wbsm2* ctx,
    wbcrypto_keybox_wbsm2_component to_save
) {
    int ret;
    size_t size = 0;
	
    if (to_save & WBCRYPTO_KEYBOX_WBSM2_PRIVATE_SEGMENT_B) {
    	if(!(ctx->loaded & WBCRYPTO_KEYBOX_WBSM2_PRIVATE_SEGMENT_B)) {
            THROW(WBCRYPTO_ERR_KEYBOX_NO_SUCH_COMPONENT);
    	}
        to_save &= ~(WBCRYPTO_KEYBOX_WBSM2_PRIVATE_SEGMENT_B);
        THROW_ONNEG(wbcrypto_keybox_wbsm2_asn1_write_private_key_segment(p, start, WBCRYPTO_KEYBOX_WBSM2_ASN1_PRIVATE_SEGMENT_B_TAG, &ctx->segmentB));
        size += ret;
    }

    if (to_save & WBCRYPTO_KEYBOX_WBSM2_PRIVATE_SEGMENT_A) {
        if (!(ctx->loaded & WBCRYPTO_KEYBOX_WBSM2_PRIVATE_SEGMENT_A)) {
            THROW(WBCRYPTO_ERR_KEYBOX_NO_SUCH_COMPONENT);
        }
        to_save &= ~(WBCRYPTO_KEYBOX_WBSM2_PRIVATE_SEGMENT_A);
        THROW_ONNEG(wbcrypto_keybox_wbsm2_asn1_write_private_key_segment(p, start, WBCRYPTO_KEYBOX_WBSM2_ASN1_PRIVATE_SEGMENT_A_TAG, &ctx->segmentA));
        size += ret;
    }
	
    if(to_save & WBCRYPTO_KEYBOX_WBSM2_PUBLIC_KEY) {
        if (!(ctx->loaded & WBCRYPTO_KEYBOX_WBSM2_PUBLIC_KEY)) {
            THROW(WBCRYPTO_ERR_KEYBOX_NO_SUCH_COMPONENT);
        }
        to_save &= ~(WBCRYPTO_KEYBOX_WBSM2_PUBLIC_KEY);
        THROW_ONNEG(wbcrypto_keybox_wbsm2_asn1_write_public_key(p, start, &ctx->pubkey));
        size += ret;
    }

    //deal with the header
    THROW_ONNEG(mbedtls_asn1_write_len(p, start, size));
    const size_t len_size = ret;
    THROW_ONNEG(mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    const size_t header_size = ret;

    ret = header_size + len_size + size;
cleanup:
    return ret;
}

int wbcrypto_keybox_wbsm2_asn1_write_public_key(
    uint8_t** p, uint8_t* start,
    wbcrypto_wbsm2_public_key* pubkey
) {
    int ret;

    //deal with subjectPublicKey BIT STRING
    uint8_t subjectPK_buf[1024] = { 0 };
    size_t subjectPK_size = 0;
    THROW_ONNZ(mbedtls_ecp_point_write_binary(&pubkey->grp, &pubkey->P, MBEDTLS_ECP_PF_UNCOMPRESSED, &subjectPK_size, subjectPK_buf, sizeof(subjectPK_buf)));
    THROW_ONNEG(mbedtls_asn1_write_bitstring(p, start, subjectPK_buf, subjectPK_size*8));
    const size_t subjectPublicKey_size = ret;
	
    //deal with AlgorithmIdentifier
    THROW_ONNEG(wbcrypto_keybox_wbsm2_asn1_write_algorithm_identifer(p, start));
    const size_t algorithmIdentifier_size = ret;

	//deal with the header
    size_t content_size = algorithmIdentifier_size + subjectPublicKey_size;
    THROW_ONNEG(mbedtls_asn1_write_len(p, start, content_size));
    const size_t len_size = ret;
    THROW_ONNEG(mbedtls_asn1_write_tag(p, start, WBCRYPTO_KEYBOX_WBSM2_ASN1_PUBLIC_KEY_TAG));
    const size_t header_size = ret;

    ret = header_size + len_size + content_size;
cleanup:
    return ret;
}

int wbcrypto_keybox_wbsm2_asn1_write_private_key_segment(
    uint8_t** p, uint8_t* start,
    int tag,
    wbcrypto_wbsm2_private_key_segment* segment
) {
    int ret;
    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    THROW_ONNZ(wbcrypto_wbsm2_load_default_group(&grp));

	//deal with hd
    THROW_ONNEG(mbedtls_asn1_write_mpi(p, start, &segment->hd));
    const size_t hd_size = ret;
	
    //deal with W
    uint8_t W_buf[1024] = { 0 };
    size_t W_buf_size = 0;
    THROW_ONNZ(mbedtls_ecp_point_write_binary(&grp, &segment->W, MBEDTLS_ECP_PF_UNCOMPRESSED, &W_buf_size, W_buf, sizeof(W_buf)));
    THROW_ONNEG(mbedtls_asn1_write_bitstring(p, start, W_buf, W_buf_size*8));
    const size_t w_size = ret;

    //deal with ec parameter
    THROW_ONNEG(wbcrypto_keybox_wbsm2_asn1_write_ec_parameter(p, start));
    const size_t ec_param_size = ret;
	
    //deal with header
    const size_t content_size = ec_param_size + w_size + hd_size;
    THROW_ONNEG(mbedtls_asn1_write_len(p, start, content_size));
    const size_t size_size = ret;
    THROW_ONNEG(mbedtls_asn1_write_tag(p, start, tag));
    const size_t tag_size = ret;
	
    ret = tag_size + size_size + content_size;
cleanup:
    mbedtls_ecp_group_free(&grp);
    return ret;
}


int wbcrypto_keybox_wbsm2_asn1_write_algorithm_identifer(
    uint8_t** p, uint8_t* start
) {
    int ret;

    //write: parameters
    THROW_ONNEG(
        mbedtls_asn1_write_oid(
            p, start,
            WBCRYPTO_OID_CURVE_SM2P256V1, sizeof(WBCRYPTO_OID_CURVE_SM2P256V1) - 1
        )
    );
    const size_t param_size = ret;

    //write: algorithm & AID header
    THROW_ONNEG(
        mbedtls_asn1_write_algorithm_identifier(
            p, start,
            MBEDTLS_OID_EC_ALG_UNRESTRICTED, sizeof(MBEDTLS_OID_EC_ALG_UNRESTRICTED) - 1,
            param_size
        )
    );
    const size_t total_size = ret;

    //the ret val is the total size
    ret = total_size;

cleanup:
    return ret;
}

size_t wbcrypto_keybox_wbsm2_asn1_algorithm_identifer_buflength() {
    const size_t algorithm_size = wbcrypto_asn1_oid_buflength(sizeof(MBEDTLS_OID_EC_ALG_UNRESTRICTED) - 1);
    const size_t param_size = wbcrypto_asn1_oid_buflength(sizeof(WBCRYPTO_OID_CURVE_SM2P256V1) - 1);
    const size_t size =
        WBCRYPTO_ASN1_TAG_BUFLENGTH
        + wbcrypto_asn1_len_buflength(param_size + algorithm_size)
        + algorithm_size
        + param_size
        ;
    return size;
}


int wbcrypto_keybox_wbsm2_asn1_write_ec_parameter(
    uint8_t** p, uint8_t* start
) {
    int ret;

    THROW_ONNEG(
        mbedtls_asn1_write_oid(
            p, start,
            WBCRYPTO_OID_CURVE_SM2P256V1, sizeof(WBCRYPTO_OID_CURVE_SM2P256V1) - 1
        )
    );
    const size_t total_size = ret;

    //the ret val is the total size
    ret = total_size;

cleanup:
    return ret;
}

size_t wbcrypto_keybox_wbsm2_asn1_ec_parameter_buflength() {
    return wbcrypto_asn1_oid_buflength(sizeof(WBCRYPTO_OID_CURVE_SM2P256V1) - 1);
}
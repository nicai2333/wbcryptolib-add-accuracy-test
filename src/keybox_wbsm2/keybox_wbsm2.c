#include <stdlib.h>
#include <string.h>
#include "wbcrypto/wbsm2.h"
#include "wbcrypto/keybox_wbsm2.h"
#include "crypto/sm4.h"
#include "wbcrypto/internal/marco_utils.h"
#include "wbcrypto/internal/keybox_wbsm2/keybox_wbsm2_asn1_read.h"
#include "wbcrypto/internal/keybox_wbsm2/keybox_wbsm2_asn1_write.h"
#include "mbedtls/asn1.h"


void wbcrypto_keybox_wbsm2_init(wbcrypto_keybox_wbsm2* ctx) {
    memset(ctx->iv, 0, sizeof(ctx->iv));
    ctx->loaded = 0;
    wbcrypto_wbsm2_public_key_init(&ctx->pubkey);
    wbcrypto_wbsm2_private_key_segment_init(&ctx->segmentA);
    wbcrypto_wbsm2_private_key_segment_init(&ctx->segmentB);
	
}

void wbcrypto_keybox_wbsm2_free(wbcrypto_keybox_wbsm2* ctx) {
    if (ctx != NULL) {
        wbcrypto_wbsm2_public_key_free(&ctx->pubkey);
        wbcrypto_wbsm2_private_key_segment_free(&ctx->segmentA);
        wbcrypto_wbsm2_private_key_segment_free(&ctx->segmentB);
    }
}


static int decrypt_encrypted_keybox(
    uint8_t* iv, size_t iv_size,
    uint8_t* key, size_t key_size,
    uint8_t* encrypted_keybox, size_t encrypted_keybox_size,
    uint8_t** decrypted_keybox, size_t* decrypted_keybox_size
);

static int encrypt_encrypted_keybox(
    uint8_t* iv, size_t iv_size,
    uint8_t* key, size_t key_size,
    uint8_t* unencrypted_keybox, size_t decrypted_keybox_size,
    uint8_t** encrypted_keybox, size_t* encrypted_keybox_size
);

static int map_asn1_error_to_malform(int ret) {
	if(ret & 0xFF00 == MBEDTLS_ERR_ASN1_INVALID_DATA & 0xFF00) {
        return WBCRYPTO_ERR_KEYBOX_MALFORMED_KEYBOX;
	} else {
        return ret;
	}
}

int wbcrypto_keybox_wbsm2_load(
    wbcrypto_keybox_wbsm2* ctx,
    uint8_t* key, size_t key_size,
    uint8_t* serialized_keybox, size_t serialized_keybox_size,
    wbcrypto_keybox_wbsm2_component to_load
) {
    int ret;

    wbcrypto_asn1_octetstring iv, encrypted_keybox;

    uint8_t* decrypted_keybox = NULL;
    size_t decrypted_keybox_size = 0;


    uint8_t* p = serialized_keybox;
    uint8_t* end = p + serialized_keybox_size;
    THROW_ONNZ(
        map_asn1_error_to_malform(
            wbcrypto_keybox_wbsm2_asn1_parse_keybox(
                &p, end, &iv, &encrypted_keybox
            )
        )
    );

	if(iv.len!=16) {
        THROW(WBCRYPTO_ERR_KEYBOX_BAD_INPUT_DATA);
	}
    memcpy(ctx->iv, iv.p, iv.len);
	
    THROW_ONNZ(
        decrypt_encrypted_keybox(
            iv.p, iv.len,
            key, key_size,
            encrypted_keybox.p, encrypted_keybox.len,
            &decrypted_keybox, &decrypted_keybox_size
        )
    );

    uint8_t* decrypted_p = decrypted_keybox;
    uint8_t* decrypted_end = decrypted_keybox + decrypted_keybox_size;
    THROW_ONNZ(
        map_asn1_error_to_malform(
        wbcrypto_keybox_wbsm2_asn1_parse_encrypted_keybox(
				&decrypted_p, decrypted_end,
				ctx, to_load
			)
        )
    );
	
cleanup:
    free(decrypted_keybox);
    return ret;
}

int wbcrypto_keybox_wbsm2_save(
    wbcrypto_keybox_wbsm2* ctx,
    uint8_t* key, size_t key_size,
    uint8_t* serialized_keybox, size_t max_serialized_keybox_size, size_t* serialized_keybox_size,
    wbcrypto_keybox_wbsm2_component to_save
) {
    int ret;
	
	//FIXME: this is a fixed constant buffer, should do for now
	//    requires buflength functions and estimate length of encryption mode to remove the constant 
    uint8_t unencrypted_keybox[1024] = {0};
    uint8_t* encrypted_keybox = NULL;
    size_t encrypted_keybox_size = 0;

    uint8_t* p = unencrypted_keybox + sizeof(unencrypted_keybox);
    uint8_t* start = unencrypted_keybox;
    THROW_ONNEG(
        wbcrypto_keybox_wbsm2_asn1_write_encrypted_keybox(
            &p, start,
            ctx, to_save
        )
    );
    size_t unencrypted_keybox_size = ret;
	
    THROW_ONNZ(
        encrypt_encrypted_keybox(
            ctx->iv, WBCRYPTO_SM4_IV_LENGTH,
            key, key_size,
            p, unencrypted_keybox_size,
            &encrypted_keybox, &encrypted_keybox_size
        )
    );

    size_t final_size = wbcrypto_keybox_wbsm2_asn1_keybox_buflength(WBCRYPTO_SM4_IV_LENGTH, encrypted_keybox_size);
	if(final_size > max_serialized_keybox_size) {
        THROW(WBCRYPTO_ERR_KEYBOX_OUTPUT_TOO_LARGE);
	}
    uint8_t* final_p = serialized_keybox + final_size;
    THROW_ONNEG(
        wbcrypto_keybox_wbsm2_asn1_write_keybox(
			&final_p, serialized_keybox,
            ctx->iv, WBCRYPTO_SM4_IV_LENGTH,
            encrypted_keybox, encrypted_keybox_size
        )
    );
    *serialized_keybox_size = final_size;
	
    ret = 0;
cleanup:
    free(encrypted_keybox);
    return ret;	
}

static int decrypt_encrypted_keybox(
    uint8_t* iv, size_t iv_size,
    uint8_t* key, size_t key_size,
    uint8_t* encrypted_keybox, size_t encrypted_keybox_size,
    uint8_t** decrypted_keybox, size_t* decrypted_keybox_size
) {
    int ret = 0;
    struct wbcrypto_sm4_context cipher_ctx;

    //SM4 requirements
    if (iv_size != WBCRYPTO_SM4_IV_LENGTH) {
        THROW(WBCRYPTO_ERR_KEYBOX_BAD_INPUT_DATA);
    }

    if (key_size != 16) {
        THROW(WBCRYPTO_ERR_KEYBOX_BAD_INPUT_DATA);
    }

    uint8_t* decrypted = (uint8_t*)malloc(encrypted_keybox_size);
    if (decrypted == NULL) {
        THROW(WBCRYPTO_ERR_KEYBOX_ALLOC_FAILED);
    }

    wbcrypto_sm4_setkey_dec(&cipher_ctx, key);

    //because the function will mutate the IV, we want to keep the IV in struct pristine
    uint8_t iv_duped[16];
    memcpy(iv_duped, iv, 16);

    int decrypt_err = (
        wbcrypto_sm4_crypt_cbc(
            &cipher_ctx,
            WBCRYPTO_SM4_DECRYPT,
            encrypted_keybox_size,
            iv_duped,
            encrypted_keybox,
            decrypted
        )
    );
    switch (decrypt_err) {
        case 0:
            ret = decrypt_err;
            break;
        case WBCRYPTO_ERR_SM4_INVALID_INPUT_LENGTH:
            THROW(WBCRYPTO_ERR_KEYBOX_MALFORMED_KEYBOX);
        default:
            THROW(decrypt_err);
    }

    *decrypted_keybox = decrypted;
    decrypted = NULL;
    *decrypted_keybox_size = encrypted_keybox_size;

cleanup:
    free(decrypted);
    return ret;
}

static int encrypt_encrypted_keybox(
    uint8_t* iv, size_t iv_size,
    uint8_t* key, size_t key_size,
    uint8_t* unencrypted_keybox, size_t unencrypted_keybox_size,
    uint8_t** encrypted_keybox, size_t* encrypted_keybox_size
) {
    int ret = 0;
    struct wbcrypto_sm4_context cipher_ctx;

    //SM4 Requirements
    if (iv_size != WBCRYPTO_SM4_IV_LENGTH) {
        THROW(WBCRYPTO_ERR_KEYBOX_BAD_INPUT_DATA);
    }

    if (key_size != 16) {
        THROW(WBCRYPTO_ERR_KEYBOX_BAD_INPUT_DATA);
    }

    size_t padded_unencrypted_keybox_size = ((unencrypted_keybox_size + 15) / 16)*16;
    uint8_t* encrypted = (uint8_t*)malloc(padded_unencrypted_keybox_size);
    if (encrypted == NULL) {
        THROW(WBCRYPTO_ERR_KEYBOX_ALLOC_FAILED);
    }

    wbcrypto_sm4_setkey_enc(&cipher_ctx, key);

	//because the function will mutate the IV, we want to keep the IV in struct pristine
    uint8_t iv_duped[16];
    memcpy(iv_duped, iv, 16);
    THROW_ONNZ(
        wbcrypto_sm4_crypt_cbc(
            &cipher_ctx,
            WBCRYPTO_SM4_ENCRYPT,
            unencrypted_keybox_size,
            iv_duped,
            unencrypted_keybox,
            encrypted
        )
    );

    *encrypted_keybox = encrypted;
    encrypted = NULL;
    *encrypted_keybox_size = padded_unencrypted_keybox_size;

cleanup:
    free(encrypted);
    return ret;
}

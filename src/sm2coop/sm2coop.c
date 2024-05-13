#include <stdlib.h>
#include <string.h>
#include "mbedtls/asn1write.h"
#include "mbedtls/asn1.h"
#include "crypto/sm2.h"
#include "wbcrypto/sm2coop.h"
#include "crypto/sm3.h"
#include "wbcrypto/internal/asn1_utils.h"
#include "wbcrypto/internal/sm2/sm2_utils.h"
#include "wbcrypto/internal/marco_utils.h"

#define CHK_RET(func, code) if((func)!=0) { ret = code; goto cleanup; }

/* SECTION: Context init & free functions */

int wbcrypto_sm2coop_load_default_group(mbedtls_ecp_group* grp) {
	return wbcrypto_sm2_load_default_group(grp);
}

void wbcrypto_sm2coop_context_init(wbcrypto_sm2coop_context* key) {
	mbedtls_ecp_group_init(&key->grp);
	mbedtls_mpi_init(&key->hd);
	mbedtls_ecp_point_init(&key->W);
	mbedtls_ecp_point_init(&key->P);
}

int wbcrypto_sm2coop_context_copy(wbcrypto_sm2coop_context* dst, const wbcrypto_sm2coop_context* src) {
	int ret = 0;
	if (dst == NULL || src == NULL) {
		ret = WBCRYPTO_ERR_SM2COOP_BAD_INPUT_DATA;
		goto cleanup;
	}
	THROW_ONNZ(mbedtls_ecp_copy(&dst->P, &src->P));
	THROW_ONNZ(mbedtls_ecp_copy(&dst->W, &src->W));
	THROW_ONNZ(mbedtls_mpi_copy(&dst->hd, &src->hd));
cleanup:
	return ret;
}

void wbcrypto_sm2coop_context_free(wbcrypto_sm2coop_context* key) {
	if (key != NULL) {
		mbedtls_ecp_group_free(&key->grp);
		mbedtls_mpi_free(&key->hd);
		mbedtls_ecp_point_free(&key->W);
		mbedtls_ecp_point_free(&key->P);
	}
}


/* SECTION : Key Generation */


/**
	write point in such ASN.1 DER format:
	SEQENCE(
		XCoordinate INTEGER,
		YCoordinate INTEGER
	)
*/
static int write_ecp_point_x_y(mbedtls_ecp_point* w, unsigned char* out, size_t max_olen, size_t* olen);

/**
*	read point in the format above
*/
static int read_ecp_point_x_y(mbedtls_ecp_point* p, const unsigned char* data, size_t data_len);

static int use_w_compute_P(wbcrypto_sm2coop_keygen_session* ctx, const mbedtls_ecp_point* w_in);


void wbcrypto_sm2coop_keygen_session_init(wbcrypto_sm2coop_keygen_session* ctx) {
	wbcrypto_sm2coop_context_init(&ctx->key);
}

int wbcrypto_sm2coop_keygen_session_copy(wbcrypto_sm2coop_keygen_session* dst, const wbcrypto_sm2coop_keygen_session* src){
	return wbcrypto_sm2coop_context_copy(&dst->key, &src->key);
}

void wbcrypto_sm2coop_keygen_session_free(wbcrypto_sm2coop_keygen_session* ctx){
	wbcrypto_sm2coop_context_free(&ctx->key);
}


int wbcrypto_sm2coop_keygen_client_send_key(
	wbcrypto_sm2coop_keygen_session* ctx,
	unsigned char* client_w, size_t max_client_w_len, size_t* client_w_len,
	int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
) {
	int ret = 0;
	THROW_ONNZ(mbedtls_ecp_gen_keypair(&ctx->key.grp, &ctx->key.hd, &ctx->key.W, f_rng, p_rng));
	THROW_ONNZ(write_ecp_point_x_y(&ctx->key.W, client_w, max_client_w_len, client_w_len));
cleanup:
	return ret;
}

int wbcrypto_sm2coop_keygen_server_exchange_key(
	wbcrypto_sm2coop_keygen_session* ctx,
	const unsigned char* client_w, size_t client_w_len,
	unsigned char* server_w, size_t max_server_w_len, size_t* server_w_len,
	int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
){
	int ret = 0;
	mbedtls_ecp_point w;
	mbedtls_ecp_point_init(&w);
	THROW_ONNZ(mbedtls_ecp_gen_keypair(&ctx->key.grp, &ctx->key.hd, &ctx->key.W, f_rng, p_rng));
	THROW_ONNZ(write_ecp_point_x_y(&ctx->key.W, server_w, max_server_w_len, server_w_len));
	CHK_RET(read_ecp_point_x_y(&w, client_w, client_w_len), WBCRYPTO_ERR_SM2COOP_BAD_INPUT_DATA);
	THROW_ONNZ(use_w_compute_P(ctx, &w));
cleanup:
	mbedtls_ecp_point_free(&w);
	return ret;
}

int wbcrypto_sm2coop_keygen_client_receive_key(
	wbcrypto_sm2coop_keygen_session* ctx,
	const unsigned char* server_w, size_t server_w_len
) {
	int ret = 0;
	mbedtls_ecp_point w;
	mbedtls_ecp_point_init(&w);
	CHK_RET(read_ecp_point_x_y(&w, server_w, server_w_len), WBCRYPTO_ERR_SM2COOP_BAD_INPUT_DATA);
	THROW_ONNZ(use_w_compute_P(ctx, &w));
cleanup:
	mbedtls_ecp_point_free(&w);
	return ret;
}


static int write_ecp_point_x_y(
	mbedtls_ecp_point* w,
	unsigned char* out, size_t max_olen, size_t* olen
) {
	int ret = 0;
	
	size_t wx_full_size = wbcrypto_asn1_mpi_buflength(&w->X);
	size_t wy_full_size = wbcrypto_asn1_mpi_buflength(&w->Y);
	size_t full_data_size = wx_full_size + wy_full_size;
	size_t full_size =
		WBCRYPTO_ASN1_TAG_BUFLENGTH
		+ wbcrypto_asn1_len_buflength(full_data_size)
		+ full_data_size
		;

	if (max_olen < full_size) {
		ret = WBCRYPTO_ERR_SM2COOP_OUTPUT_TOO_LARGE;
		goto cleanup;
	}

	unsigned char* p = out + full_size;
	WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_mpi(&p, out, &w->Y));
	WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_mpi(&p, out, &w->X));
	WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_len(&p, out, full_data_size));
	WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_tag(&p, out, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
	*olen = full_size;
	ret = 0; // their retval is non-zero on success
cleanup:
	return ret;
}

static int read_ecp_point_x_y(
	mbedtls_ecp_point* p,
	const unsigned char* data, size_t data_len
) {
	int ret = 0;
	unsigned char* now = (unsigned char*)data;
	const unsigned char* end = data + data_len;
	size_t body_length = 0;
	THROW_ONNZ(mbedtls_asn1_get_tag(&now, end, &body_length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
	THROW_ONNZ(mbedtls_asn1_get_mpi(&now, end, &p->X));
	THROW_ONNZ(mbedtls_asn1_get_mpi(&now, end, &p->Y));
	THROW_ONNZ(mbedtls_mpi_lset(&p->Z, 1));
cleanup:
	return ret;
}

static int use_w_compute_P(wbcrypto_sm2coop_keygen_session* ctx, const mbedtls_ecp_point* w_in)
{
	int ret = 0;
	mbedtls_mpi tmp;
	mbedtls_mpi_init(&tmp);
	THROW_ONNZ(mbedtls_mpi_lset(&tmp, -1));
	//P = hd*W - G
	THROW_ONNZ(mbedtls_ecp_muladd(&ctx->key.grp, &ctx->key.P, &ctx->key.hd, w_in, &tmp, &ctx->key.grp.G));
cleanup:
	mbedtls_mpi_free(&tmp);
	return ret;
}


/* SECTION: ENCRYPT & COOP DECRYPT */


int wbcrypto_sm2coop_encrypt(
	wbcrypto_sm2coop_context* ctx,
	const unsigned char* buffer, size_t	blen,
	unsigned char* out, size_t max_olen, size_t* olen,
	int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
) {
	//a complete wrapper to sm2
	wbcrypto_sm2_context ictx = { ctx->grp, ctx->hd, ctx->P };
	const int ret = wbcrypto_sm2_encrypt_asn1(
		&ictx,
		buffer, blen,
		out, max_olen, olen,
		f_rng, p_rng
	);
	switch (ret) {
		case WBCRYPTO_ERR_SM2_OUTPUT_TOO_LARGE:
			return WBCRYPTO_ERR_SM2COOP_OUTPUT_TOO_LARGE;
		default:
			return ret;
	}
}


void wbcrypto_sm2coop_decrypt_client_session_init(wbcrypto_sm2coop_decrypt_client_session* ctx) {
	mbedtls_ecp_point_init(&ctx->c1point);
	ctx->total_size = 0;
	ctx->c2_offset = 0;
	ctx->c2_len = 0;
	ctx->c3_offset = 0;
	ctx->c3_len = 0;
}

int wbcrypto_sm2coop_decrypt_client_session_copy(
	wbcrypto_sm2coop_decrypt_client_session* dst,
	const wbcrypto_sm2coop_decrypt_client_session* src
) {
	int ret;
	if(dst == NULL || src == NULL) {
		return WBCRYPTO_ERR_SM2COOP_BAD_INPUT_DATA;
	}
	THROW_ONNZ(mbedtls_mpi_copy(&dst->c1point.X, &src->c1point.X));
	THROW_ONNZ(mbedtls_mpi_copy(&dst->c1point.Y, &src->c1point.Y));
	THROW_ONNZ(mbedtls_mpi_copy(&dst->c1point.Z, &src->c1point.Z));
	dst->total_size = src->total_size;
	dst->c2_offset = src->c2_offset;
	dst->c2_len = src->c2_len;
	dst->c3_offset = src->c3_offset;
	dst->c3_len = src->c3_len;
 cleanup:
	return ret;
}

void wbcrypto_sm2coop_decrypt_client_session_free(wbcrypto_sm2coop_decrypt_client_session* ctx) {
	if (ctx != NULL) {
		mbedtls_ecp_point_free(&ctx->c1point);
	}
}


int wbcrypto_sm2coop_decrypt_client_start(
	wbcrypto_sm2coop_context* ctx,
	wbcrypto_sm2coop_decrypt_client_session* decrypt_ctx,
	const unsigned char* ciphertext, size_t clen,
	unsigned char* out, size_t max_olen, size_t* olen
) {
	int ret;

	/*parse ASN.1 into decrypt ctx and setup C1 Data Offset to copy*/
	unsigned char* now = (unsigned char*)ciphertext;
	const unsigned char* end = ciphertext + clen;
	size_t body_length = 0;
	size_t c1_full_offset, c1_full_size;
	size_t c2_data_offset, c2_data_size = 0;
	size_t c3_data_offset, c3_data_size = 0;
	THROW_ONNZ(mbedtls_asn1_get_tag(&now, end, &body_length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
	c1_full_offset = now - ciphertext;
	THROW_ONNZ(mbedtls_asn1_get_mpi(&now, end, &decrypt_ctx->c1point.X));
	THROW_ONNZ(mbedtls_asn1_get_mpi(&now, end, &decrypt_ctx->c1point.Y));
	THROW_ONNZ(mbedtls_mpi_lset(&decrypt_ctx->c1point.Z, 1));
	c1_full_size = now - ciphertext - c1_full_offset;
	THROW_ONNZ(mbedtls_asn1_get_tag(&now, end, &c3_data_size, MBEDTLS_ASN1_OCTET_STRING));
	c3_data_offset = now - ciphertext;
	now += c3_data_size;
	THROW_ONNZ(mbedtls_asn1_get_tag(&now, end, &c2_data_size, MBEDTLS_ASN1_OCTET_STRING));
	c2_data_offset = now - ciphertext;
	now += c2_data_size;
	decrypt_ctx->total_size = clen;
	decrypt_ctx->c2_offset = c2_data_offset;
	decrypt_ctx->c2_len = c2_data_size;
	decrypt_ctx->c3_offset = c3_data_offset;
	decrypt_ctx->c3_len = c3_data_size;

	//construct the ASN.1 structure for request
	body_length = c1_full_size;
	size_t full_length =
		WBCRYPTO_ASN1_TAG_BUFLENGTH
		+ wbcrypto_asn1_len_buflength(body_length)
		+ body_length
		;

	if (max_olen < full_length) {
		return WBCRYPTO_ERR_SM2COOP_OUTPUT_TOO_LARGE;
	}
	
	unsigned char* p = out + full_length;
	memcpy(p - body_length, ciphertext + c1_full_offset, c1_full_size);
	p -= body_length;
	WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_len(&p, out, c1_full_size));
	WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_tag(&p, out, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
	ret = 0; // clear the ret
	*olen = full_length;

cleanup:
	return ret;
}

int wbcrypto_sm2coop_decrypt_server_respond(
	wbcrypto_sm2coop_context* key,
	const unsigned char* req, size_t req_len,
	unsigned char* resp, size_t max_resplen, size_t* resplen,
	int(*f_rng)(void*, unsigned char*, size_t), void* p_rng
) {
	int ret;
	mbedtls_ecp_point C_1;
	mbedtls_ecp_point_init(&C_1);
	mbedtls_ecp_point C_s1;
	mbedtls_ecp_point_init(&C_s1);

	CHK_RET(read_ecp_point_x_y(&C_1, req, req_len), WBCRYPTO_ERR_SM2COOP_BAD_INPUT_DATA);
	//C_s1 = [hd_s]C_1
	THROW_ONNZ(mbedtls_ecp_mul(&key->grp, &C_s1, &key->hd, &C_1, f_rng, p_rng));
	THROW_ONNZ(write_ecp_point_x_y(&C_s1, resp, max_resplen, resplen));
	
cleanup:
	mbedtls_ecp_point_free(&C_s1);
	mbedtls_ecp_point_free(&C_1);
	return ret;
}

int wbcrypto_sm2coop_decrypt_client_complete(
	wbcrypto_sm2coop_context* key,
	wbcrypto_sm2coop_decrypt_client_session* decrypt_ctx,
	const unsigned char* resp, size_t resplen,
	const unsigned char* ciphertext, size_t clen,
	unsigned char* out, size_t max_olen, size_t* olen
) {
	int ret;
	unsigned char* tmp = NULL;
	size_t tmp_len;
	unsigned char* tmp2 = NULL;
	size_t tmp2_len;
	mbedtls_ecp_point P1;
	mbedtls_ecp_point_init(&P1);
	mbedtls_ecp_point P2;
	mbedtls_ecp_point_init(&P2);
	mbedtls_mpi neg1;
	mbedtls_mpi_init(&neg1);
	THROW_ONNZ(mbedtls_mpi_lset(&neg1, -1));

	//validate and recover pointer address
	if(decrypt_ctx->total_size != clen) {
		return WBCRYPTO_ERR_SM2COOP_BAD_INPUT_DATA;
	}
	const unsigned char* c2 = decrypt_ctx->c2_offset + ciphertext;
	size_t c2_len = decrypt_ctx->c2_len;
	const unsigned char* c3 = decrypt_ctx->c3_offset + ciphertext;
	size_t c3_len = decrypt_ctx->c3_len;

	tmp_len = 65 + c2_len + c3_len;
	if (NULL == (tmp = calloc(tmp_len, sizeof(unsigned char)))) {
		ret = WBCRYPTO_ERR_SM2COOP_ALLOC_FAILED;
		goto cleanup;
	}
	tmp2_len = tmp_len;
	if (NULL == (tmp2 = calloc(tmp2_len, sizeof(unsigned char)))) {
		ret = WBCRYPTO_ERR_SM2COOP_ALLOC_FAILED;
		goto cleanup;
	}

	//parse C_S1 into P1
	CHK_RET(read_ecp_point_x_y(&P1, resp, resplen), WBCRYPTO_ERR_SM2COOP_BAD_INPUT_DATA);

	//P1 = C_s1 P2 = C_1
	//P1 = [hd_a]C_s1 + [-1]C_1 = [hd_a]P1 + [-1]P2
	THROW_ONNZ(mbedtls_ecp_muladd(&(key->grp), &P1, &key->hd, &P1, &neg1, &decrypt_ctx->c1point));

	// tmp2 = KDF(P1.x1||P1.y, klen)
	size_t x1y1_len = tmp_len;
	// tmp = P1.x1||P1.y
	THROW_ONNZ(write_point_x_y(&(key->grp), &P1, tmp, &x1y1_len));
	THROW_ONNZ(kdf(tmp2, tmp, x1y1_len, c2_len));
	//M = C2 XOR KDF(P1.x1||P1.y, klen) = C2 XOR tmp2
	if (max_olen < c2_len) {
		return WBCRYPTO_ERR_SM2COOP_OUTPUT_TOO_LARGE;
	}
	size_t i = 0;
	for (; i < c2_len; i++) {
		out[i] = c2[i] ^ tmp2[i];
	}
	*olen = c2_len;

	// tmp2 = Hash(P1.x1||M||P1.y1)	
	size_t cat_len = tmp_len;
	THROW_ONNZ(write_x2_m_y2(&(key->grp), &P1, c2, c2_len, tmp, &cat_len));
	wbcrypto_sm3(tmp, tmp_len, tmp2);

	//assert Hash(P1.x1||M||P1.y1) == c3, ie tmp2 == c3
	if (!strncmp((char*)tmp2, (char*)c3, c3_len)) {
		return WBCRYPTO_ERR_SM2COOP_GENERIC_FAILURE;
	}

cleanup:
	mbedtls_mpi_free(&neg1);
	mbedtls_ecp_point_free(&P2);
	mbedtls_ecp_point_free(&P1);
	free(tmp2);
	free(tmp);
	return ret;
}


/* SECTION: COOP SIGN & VERIFY */


//write mpi r and s in ASN.1 struct format (same as SM2 Signature)
static int write_r_s(const mbedtls_mpi* r, const mbedtls_mpi* s, unsigned char* out, size_t max_olen, size_t* olen);

//read mpi r and s in ASN.1 struct format (same as SM2 Signature)
static int read_r_s(mbedtls_mpi* r, mbedtls_mpi* s, const unsigned char* data, size_t data_len);


void wbcrypto_sm2coop_sign_client_session_init(wbcrypto_sm2coop_sign_client_session* ctx) {
	mbedtls_mpi_init(&ctx->k);
}

int wbcrypto_sm2coop_sign_client_session_copy(
	wbcrypto_sm2coop_sign_client_session* dst,
	const wbcrypto_sm2coop_sign_client_session* src
) {
	return mbedtls_mpi_copy(&dst->k, &src->k);
}

void wbcrypto_sm2coop_sign_client_session_free(wbcrypto_sm2coop_sign_client_session* ctx) {
	mbedtls_mpi_free(&ctx->k);
}


int wbcrypto_sm2coop_sign_client_start(
	wbcrypto_sm2coop_context* ctx,
	wbcrypto_sm2coop_sign_client_session* sign_ctx,
	const unsigned char* msg, size_t msglen,
	unsigned char* dgst, size_t max_dgstlen, size_t* dgstlen,
	unsigned char* req, size_t max_reqlen, size_t* reqlen,
	int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
) {
	return wbcrypto_sm2coop_sign_client_start_withID(
		ctx,
		sign_ctx,
		(unsigned char*)sm2_default_id, sm2_default_id_length,
		msg, msglen,
		dgst, max_dgstlen, dgstlen,
		req, max_reqlen, reqlen,
		f_rng, p_rng
	);
}

#include <time.h>
int wbcrypto_sm2coop_sign_client_start_withID(
	wbcrypto_sm2coop_context* ctx,
	wbcrypto_sm2coop_sign_client_session* sign_ctx,
	const unsigned char* id, size_t idlen,
	const unsigned char* msg, size_t msglen,
	unsigned char* dgst, size_t max_dgstlen, size_t* dgstlen,
	unsigned char* req, size_t max_reqlen, size_t* reqlen,
	int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
) {
	int ret;
	wbcrypto_sm2_context wrapper = { ctx->grp, ctx->hd, ctx->P };
	mbedtls_ecp_point q;
	mbedtls_ecp_point_init(&q);

	/* compute digest */
	if(max_dgstlen < SM3_DIGEST_LENGTH) {
		ret = WBCRYPTO_ERR_SM2COOP_OUTPUT_TOO_LARGE;
		goto cleanup;
	}

	THROW_ONNZ(wbcrypto_sm2_compute_hashedMbar(
		&wrapper,
		id, idlen,
		msg, msglen,
		dgst
	));
	*dgstlen = SM3_DIGEST_LENGTH;
	
	//gen k in [1,n-1]
	THROW_ONNZ(mbedtls_ecp_gen_privkey(&ctx->grp, &sign_ctx->k, f_rng, p_rng));

	//Q = kP+kG
    clock_t begin_t, end_t;
    begin_t = clock();
    size_t times = 1000;
    for (int i = 0; i < times; ++i) {
        THROW_ONNZ(mbedtls_ecp_muladd(&ctx->grp, &q, &sign_ctx->k, &ctx->P, &sign_ctx->k, &ctx->grp.G));
    }
    end_t = clock();
    double total_time = 1.0*(end_t-begin_t)/CLOCKS_PER_SEC;
	printf("%s, run %d times, total time: %f s, one time: %f s\n",
       	   "test", times, total_time, times/total_time);

	//write Q
	THROW_ONNZ(write_ecp_point_x_y(&q, req, max_reqlen, reqlen));

cleanup:
	mbedtls_ecp_point_free(&q);
	return ret;
}

int wbcrypto_sm2coop_sign_server_respond(
	wbcrypto_sm2coop_context* ctx,
	const unsigned char* dgst, size_t dgst_len,
	const unsigned char* req, size_t req_len,
	unsigned char* resp, size_t max_resplen, size_t* resplen,
	int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
) {
	int ret;
	mbedtls_mpi r, s;
	mbedtls_ecp_point q;
	mbedtls_ecp_point tmpP;
	mbedtls_mpi tmp;
	mbedtls_mpi tmpK;

	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);
	mbedtls_ecp_point_init(&q);
	mbedtls_mpi_init(&tmp);
	mbedtls_mpi_init(&tmpK);
	mbedtls_ecp_point_init(&tmpP);

	/* load request */
	THROW_ONNZ(read_ecp_point_x_y(&q, req, req_len));

	/* run computations */
	THROW_ONNZ(mbedtls_mpi_lset(&tmp, 1));
	//gen k in [1,n-1]
	THROW_ONNZ(mbedtls_ecp_gen_privkey(&ctx->grp, &tmpK, f_rng, p_rng));
	// tmpP = k*W + Q
	THROW_ONNZ(mbedtls_ecp_muladd(&ctx->grp, &tmpP, &tmpK, &ctx->W, &tmp, &q));
	//Hashed M bar
	THROW_ONNZ(mbedtls_mpi_read_binary(&tmp, dgst, dgst_len));
	//r = (H(m)+x1) mod n
	THROW_ONNZ(mbedtls_mpi_add_mpi(&r, &tmp, &tmpP.X));
	THROW_ONNZ(mbedtls_mpi_mod_mpi(&r, &r, &ctx->grp.N));

	//tmp = hd^-1
	THROW_ONNZ(mbedtls_mpi_inv_mod(&tmp, &ctx->hd, &ctx->grp.N));
	//hd^-1 * r
	THROW_ONNZ(mbedtls_mpi_mul_mpi(&tmp, &tmp, &r));
	//hd^-1 * r + k
	THROW_ONNZ(mbedtls_mpi_add_mpi(&tmp, &tmp, &tmpK));
	//s = (hd^-1 * r + k) mod n
	THROW_ONNZ(mbedtls_mpi_mod_mpi(&s, &tmp, &ctx->grp.N));

	/* write response */
	THROW_ONNZ(write_r_s(&r, &s, resp, max_resplen, resplen));

cleanup:
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
	mbedtls_mpi_free(&tmp);
	mbedtls_mpi_init(&tmpK);
	mbedtls_ecp_point_free(&tmpP);
	mbedtls_ecp_point_free(&q);
	return ret;
}

int wbcrypto_sm2coop_sign_client_complete(
	wbcrypto_sm2coop_context* ctx,
	wbcrypto_sm2coop_sign_client_session* sign_ctx,
	const unsigned char* resp, size_t resplen,
	unsigned char* sig, size_t max_siglen, size_t* siglen
) {
	int ret;
	mbedtls_mpi r, s;
	mbedtls_mpi tmp;
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);
	mbedtls_mpi_init(&tmp);

	/* read response */
	THROW_ONNZ(read_r_s(&r, &s, resp, resplen));

	//tmp = hd^-1
	THROW_ONNZ(mbedtls_mpi_inv_mod(&tmp, &ctx->hd, &ctx->grp.N));
	// hd^-1 * s
	THROW_ONNZ(mbedtls_mpi_mul_mpi(&tmp, &tmp, &s));
	// hd^-1 * s + k
	THROW_ONNZ(mbedtls_mpi_add_mpi(&tmp, &tmp, &sign_ctx->k));
	// hd^-1 * s + k - r
	THROW_ONNZ(mbedtls_mpi_sub_mpi(&tmp, &tmp, &r));
	// s = (hd^-1 * s + k - r )mod n
	THROW_ONNZ(mbedtls_mpi_mod_mpi(&s, &tmp, &ctx->grp.N));

	/* write signature */
	THROW_ONNZ(write_r_s(&r, &s, sig, max_siglen, siglen));

cleanup:
	mbedtls_mpi_free(&tmp);
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);

	return ret;
}


int wbcrypto_sm2coop_verify(
	wbcrypto_sm2coop_context* ctx,
	const unsigned char* message, size_t msglen,
	const unsigned char* sig, size_t siglen
) {
	return wbcrypto_sm2coop_verify_withID(
		ctx,
		(const unsigned char*)sm2_default_id, sm2_default_id_length,
		message, msglen,
		sig, siglen
	);
}

int wbcrypto_sm2coop_verify_withID(
	wbcrypto_sm2coop_context* ctx,
	const unsigned char* id, size_t idlen,
	const unsigned char* msg, size_t msglen,
	const unsigned char* sig, size_t siglen
) {
	int ret;
	mbedtls_mpi r, s;
	mbedtls_mpi t;
	mbedtls_ecp_point pointG;
	wbcrypto_sm2_context wrapper = { ctx->grp, ctx->hd, ctx->P };
	unsigned char hashMbar[SM3_DIGEST_LENGTH];

	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);
	mbedtls_mpi_init(&t);
	mbedtls_ecp_point_init(&pointG);

	THROW_ONNZ(read_r_s(&r, &s, sig, siglen));

	/* check r, s in [1, n-1]*/
	if (mbedtls_mpi_cmp_int(&r, 1) == -1 || mbedtls_mpi_cmp_int(&s, 1) == -1 
		|| mbedtls_mpi_cmp_mpi(&r, &(ctx->grp.N)) == 1 || mbedtls_mpi_cmp_mpi(&s, &(ctx->grp.N)) == 1
	) {
		ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
		goto cleanup;
	}

	/*  t = (r + s) mod n  */
	THROW_ONNZ(mbedtls_mpi_add_mpi(&t, &r, &s));
	THROW_ONNZ(mbedtls_mpi_mod_mpi(&t, &t, &(ctx->grp.N)));

	/* check t  != 0 */
	if (mbedtls_mpi_cmp_int(&t, 0) == 0) {
		ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
		goto cleanup;
	}

	/* compute pointG= (x, y) = sG + tP, P is pub_key */
	THROW_ONNZ(mbedtls_ecp_muladd(&ctx->grp, &pointG, &s, &(ctx->grp.G), &t, &ctx->P));

	/* tmp <- R = (e + x1) mod n  ;x1 in pointG */
	/* t <- e */
	THROW_ONNZ(wbcrypto_sm2_compute_hashedMbar(
		&wrapper,
		id, idlen,
		msg, msglen,
		hashMbar
	));
	THROW_ONNZ(mbedtls_mpi_read_binary(&t, hashMbar, SM3_DIGEST_LENGTH));

	/* t <- e + x1 */
	THROW_ONNZ(mbedtls_mpi_add_mpi(&t, &t, &(pointG.X)));
	/*t <- R = t mod n*/
	THROW_ONNZ(mbedtls_mpi_mod_mpi(&t, &t, &(ctx->grp.N)));

	/*t (R) = r ?*/
	if (mbedtls_mpi_cmp_mpi(&t, &r) != 0) {
		ret = WBCRYPTO_ERR_SM2COOP_VERIFY_FAILED;
	}

cleanup:
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
	mbedtls_mpi_free(&t);
	mbedtls_ecp_point_free(&pointG);
	return ret;
}


static int write_r_s(
	const mbedtls_mpi* r, const mbedtls_mpi* s,
	unsigned char* out, size_t max_olen, size_t* olen
) {
	int ret;
	size_t sequence_body_size =
		wbcrypto_asn1_mpi_buflength(r)
		+ wbcrypto_asn1_mpi_buflength(s)
		;

	size_t expected_size =
		WBCRYPTO_ASN1_TAG_BUFLENGTH
		+ wbcrypto_asn1_len_buflength(sequence_body_size)
		+ sequence_body_size
		;

	if (expected_size > max_olen) {
		return WBCRYPTO_ERR_SM2_OUTPUT_TOO_LARGE;
	}

	*olen = expected_size;
	unsigned char* p = out + expected_size;
	WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_mpi(&p, out, s));
	WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_mpi(&p, out, r));
	WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_len(&p, out, sequence_body_size));
	WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_tag(&p, out, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
	ret = 0;//asn1 writer have pos return value on success
cleanup:
	return ret;
}

static int read_r_s(
	mbedtls_mpi* r, mbedtls_mpi* s,
	const unsigned char* data, size_t data_len
) {
	int ret;
	unsigned char* now = (unsigned char*)data;
	const unsigned char* end = data + data_len;
	size_t body_length = 0;
	THROW_ONNZ(mbedtls_asn1_get_tag(&now, end, &body_length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
	THROW_ONNZ(mbedtls_asn1_get_mpi(&now, end, r));
	THROW_ONNZ(mbedtls_asn1_get_mpi(&now, end, s));
cleanup:
	return ret;
}


#if defined(WBCRYPTO_SELF_TEST)
int wbcrypto_sm2coop_self_test(int verbose);
#endif
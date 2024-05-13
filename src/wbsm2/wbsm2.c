#include "wbcrypto/wbsm2.h"
#include "wbcrypto/sm2coop.h"
#include "wbcrypto/internal/sm2/sm2_utils.h"
#include "wbcrypto/internal/marco_utils.h"
#include "wbcrypto/internal/param_chk_utils.h"
#include <stdlib.h>
#include <string.h>

/* Parameter validation macros based on param_chk_util.h */
#define WBSM2_VALIDATE_RET( cond )    \
    WBCRYPTO_INTERNAL_VALIDATE_RET( cond, WBCRYPTO_ERR_WBSM2_BAD_INPUT_DATA )
#define WBSM2_VALIDATE( cond )        \
    WBCRYPTO_INTERNAL_VALIDATE( cond )


int wbcrypto_wbsm2_load_default_group(mbedtls_ecp_group* grp) {
	return wbcrypto_sm2coop_load_default_group(grp);
}


void wbcrypto_wbsm2_public_key_init(wbcrypto_wbsm2_public_key* key) {
	mbedtls_ecp_group_init(&key->grp);
	mbedtls_ecp_point_init(&key->P);
}

int wbcrypto_wbsm2_public_key_copy(wbcrypto_wbsm2_public_key* dst, const wbcrypto_wbsm2_public_key* src) {
	int ret = 0;
	if (dst == NULL || src == NULL) {
		ret = WBCRYPTO_ERR_SM2COOP_BAD_INPUT_DATA;
		goto cleanup;
	}
	MBEDTLS_MPI_CHK(mbedtls_ecp_copy(&dst->P, &src->P));
cleanup:
	return ret;
}

void wbcrypto_wbsm2_public_key_free(wbcrypto_wbsm2_public_key* key) {
	if (key != NULL) {
		mbedtls_ecp_group_free(&key->grp);
		mbedtls_ecp_point_free(&key->P);
	}
}


void wbcrypto_wbsm2_private_key_segment_init(wbcrypto_wbsm2_private_key_segment* key) {
	mbedtls_mpi_init(&key->hd);
	mbedtls_ecp_point_init(&key->W);
}

int wbcrypto_wbsm2_private_key_segment_copy(wbcrypto_wbsm2_private_key_segment* dst, const wbcrypto_wbsm2_private_key_segment* src) {
	int ret = 0;
	if (dst == NULL || src == NULL) {
		ret = WBCRYPTO_ERR_SM2COOP_BAD_INPUT_DATA;
		goto cleanup;
	}
	MBEDTLS_MPI_CHK(mbedtls_ecp_copy(&dst->W, &src->W));
	MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&dst->hd, &src->hd));
cleanup:
	return ret;
}

void wbcrypto_wbsm2_private_key_segment_free(wbcrypto_wbsm2_private_key_segment* key) {
	if (key != NULL) {
		mbedtls_mpi_free(&key->hd);
		mbedtls_ecp_point_free(&key->W);
	}
}


static int mbedtls_ecp_point_copy(struct mbedtls_ecp_point* dest, const struct mbedtls_ecp_point* src) {
	int ret = 0;
	MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&dest->X, &src->X));
	MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&dest->Y, &src->Y));
	MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&dest->Z, &src->Z));
cleanup:
	return ret;
}

int wbcrypto_wbsm2_generate_key(
	wbcrypto_wbsm2_public_key* pubkey,
	wbcrypto_wbsm2_private_key_segment* segmentA,
	wbcrypto_wbsm2_private_key_segment* segmentB,
	int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
) {
	int ret = 0;
	wbcrypto_sm2coop_keygen_session A, B;
	uint8_t client_w[1024] = { 0 };
	size_t client_w_size = 0;
	uint8_t server_w[1024] = { 0 };
	size_t server_w_size = 0;

	wbcrypto_sm2coop_keygen_session_init(&A);
	wbcrypto_sm2coop_keygen_session_init(&B);

	WBSM2_VALIDATE_RET(pubkey != NULL);
	WBSM2_VALIDATE_RET(segmentA != NULL);
	WBSM2_VALIDATE_RET(segmentB != NULL);
	WBSM2_VALIDATE_RET(f_rng != NULL);
	
	//wrap: use the pubkey's group
	A.key.grp = pubkey->grp;
	B.key.grp = pubkey->grp;
	
	MBEDTLS_MPI_CHK(wbcrypto_sm2coop_keygen_client_send_key(
		&A,
		client_w, sizeof(client_w), &client_w_size,
		f_rng, p_rng
	));

	MBEDTLS_MPI_CHK(wbcrypto_sm2coop_keygen_server_exchange_key(
		&B,
		client_w, client_w_size,
		server_w, sizeof(server_w), &server_w_size,
		f_rng, p_rng
	));

	MBEDTLS_MPI_CHK(wbcrypto_sm2coop_keygen_client_receive_key(
		&A,
		server_w, server_w_size
	));
	
	MBEDTLS_MPI_CHK(mbedtls_ecp_point_copy(&pubkey->P, &A.key.P));

	MBEDTLS_MPI_CHK(mbedtls_ecp_point_copy(&segmentA->W, &A.key.W));
	MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&segmentA->hd, &A.key.hd));

	MBEDTLS_MPI_CHK(mbedtls_ecp_point_copy(&segmentB->W, &B.key.W));
	MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&segmentB->hd, &B.key.hd));
	
cleanup:
	//wrap: clean up the wrap part
	mbedtls_ecp_group_init(&A.key.grp);
	mbedtls_ecp_group_init(&B.key.grp);
	wbcrypto_sm2coop_keygen_session_free(&A);
	wbcrypto_sm2coop_keygen_session_free(&B);
	return ret;
}


int wbcrypto_wbsm2_encrypt(
	wbcrypto_wbsm2_public_key* ctx,
	const unsigned char* buffer, size_t	blen,
	unsigned char* out, size_t max_olen, size_t* olen,
	int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
) {
	int ret = 0;

	WBSM2_VALIDATE_RET(ctx != NULL);
	WBSM2_VALIDATE_RET(buffer != NULL);
	WBSM2_VALIDATE_RET(blen > 0);
	WBSM2_VALIDATE_RET(out != NULL);
	WBSM2_VALIDATE_RET(max_olen > 0);
	WBSM2_VALIDATE_RET(olen > 0);
	WBSM2_VALIDATE_RET(f_rng != NULL);
	
	wbcrypto_sm2coop_context wrap_ctx;
	wrap_ctx.grp = ctx->grp;
	wrap_ctx.P = ctx->P;
	
	MBEDTLS_MPI_CHK(wbcrypto_sm2coop_encrypt(
		&wrap_ctx,
		buffer, blen,
		out, max_olen, olen,
		f_rng, p_rng
	));
	
cleanup:
	return ret;
}


void wbcrypto_wbsm2_decrypt_session_init(wbcrypto_wbsm2_decrypt_session* ctx) {
	mbedtls_ecp_point_init(&ctx->c1point);
	ctx->total_size = 0;
	ctx->req_buf = NULL;
	ctx->req_size = 0;
	ctx->resp_buf = NULL;
	ctx->resp_size = 0;
	ctx->c2_offset = 0;
	ctx->c2_len = 0;
	ctx->c3_offset = 0;
	ctx->c3_len = 0;
}


static int buffer_copy(uint8_t** dst_buf, size_t* dst_buf_size, uint8_t* src_buf, size_t src_buf_size) {
	int ret = 0;

	if (*dst_buf != NULL) {
		free(*dst_buf);
		*dst_buf = NULL;
		*dst_buf_size = 0;
	}

	if (src_buf == NULL) {
		*dst_buf = NULL;
		*dst_buf_size = 0;
	} else {
		*dst_buf = malloc(src_buf_size);
		if (*dst_buf == NULL) {
			return WBCRYPTO_ERR_SM2COOP_ALLOC_FAILED;
		}
		MBEDTLS_MPI_CHK(memcpy(*dst_buf, src_buf, src_buf_size));
		*dst_buf_size = src_buf_size;
	}
	
cleanup:
	return ret;
}

int wbcrypto_wbsm2_decrypt_session_copy(wbcrypto_wbsm2_decrypt_session* dst, const wbcrypto_wbsm2_decrypt_session* src) {
	int ret = 0;
	if (dst == NULL || src == NULL) {
		return WBCRYPTO_ERR_SM2COOP_BAD_INPUT_DATA;
	}
	
	MBEDTLS_MPI_CHK(mbedtls_ecp_point_copy(&dst->c1point, &src->c1point));
	dst->total_size = src->total_size;

	MBEDTLS_MPI_CHK(buffer_copy(&dst->req_buf, &dst->req_size, src->req_buf, src->req_size));
	MBEDTLS_MPI_CHK(buffer_copy(&dst->resp_buf, &dst->resp_size, src->resp_buf, src->resp_size));
	
	dst->c2_offset = src->c2_offset;
	dst->c2_len = src->c2_len;
	dst->c3_offset = src->c3_offset;
	dst->c3_len = src->c3_len;

cleanup:
	return ret;
}

void wbcrypto_wbsm2_decrypt_session_free(wbcrypto_wbsm2_decrypt_session* ctx) {
	if (ctx != NULL) {
		mbedtls_ecp_point_free(&ctx->c1point);
		free(ctx->req_buf);
		free(ctx->resp_buf);
	}
}


int wbcrypto_wbsm2_decrypt_stepA(
	wbcrypto_wbsm2_public_key* public_key,
	wbcrypto_wbsm2_private_key_segment* segmentA,
	wbcrypto_wbsm2_decrypt_session* decrypt_ctx,
	const unsigned char* ciphertext, size_t clen
) {
	int ret = 0;
	wbcrypto_sm2coop_context wrap_ctx;
	wbcrypto_sm2coop_decrypt_client_session wrap_decrypt_ctx;
	uint8_t* req_buf = NULL;
	
	WBSM2_VALIDATE_RET(public_key != NULL);
	WBSM2_VALIDATE_RET(segmentA != NULL);
	WBSM2_VALIDATE_RET(decrypt_ctx != NULL);
	WBSM2_VALIDATE_RET(ciphertext != NULL);
	WBSM2_VALIDATE_RET(clen > 0);
	
	wbcrypto_sm2coop_decrypt_client_session_init(&wrap_decrypt_ctx);
	wrap_ctx.grp = public_key->grp;
	wrap_ctx.P = public_key->P;
	wrap_ctx.W = segmentA->W;
	wrap_ctx.hd = segmentA->hd;

	const size_t req_buf_size = 1024;
	size_t req_buf_used = 0;
	req_buf = malloc(req_buf_size);
	if(req_buf == NULL) {
		ret = WBCRYPTO_ERR_WBSM2_ALLOC_FAILED;
		goto cleanup;
	}

	MBEDTLS_MPI_CHK(wbcrypto_sm2coop_decrypt_client_start(
		&wrap_ctx,
		&wrap_decrypt_ctx,
		ciphertext, clen,
		req_buf, req_buf_size, &req_buf_used 
	));

	MBEDTLS_MPI_CHK(mbedtls_ecp_point_copy(&decrypt_ctx->c1point, &wrap_decrypt_ctx.c1point));
	decrypt_ctx->total_size = wrap_decrypt_ctx.total_size;
	decrypt_ctx->c2_len = wrap_decrypt_ctx.c2_len;
	decrypt_ctx->c2_offset = wrap_decrypt_ctx.c2_offset;
	decrypt_ctx->c3_len = wrap_decrypt_ctx.c3_len;
	decrypt_ctx->c3_offset = wrap_decrypt_ctx.c3_offset;

	if(decrypt_ctx->req_buf != NULL) {
		free(decrypt_ctx->req_buf);
		decrypt_ctx->req_buf = NULL;
	}
	decrypt_ctx->req_buf = req_buf;
	req_buf = NULL;
	decrypt_ctx->req_size = req_buf_used;
	
cleanup:
	free(req_buf);
	return ret;
}

int wbcrypto_wbsm2_decrypt_stepB(
	wbcrypto_wbsm2_public_key* public_key, 
	wbcrypto_wbsm2_private_key_segment* segmentB, 
	wbcrypto_wbsm2_decrypt_session* decrypt_ctx, 
	int (* f_rng)(void*, unsigned char*, size_t), void* p_rng
) {
	int ret = 0;
	wbcrypto_sm2coop_context wrap_ctx;
	uint8_t* resp_buf = NULL;

	WBSM2_VALIDATE_RET(public_key != NULL);
	WBSM2_VALIDATE_RET(segmentB != NULL);
	WBSM2_VALIDATE_RET(decrypt_ctx != NULL);
	WBSM2_VALIDATE_RET(f_rng != NULL);
	
	wrap_ctx.grp = public_key->grp;
	wrap_ctx.P = public_key->P;
	wrap_ctx.W = segmentB->W;
	wrap_ctx.hd = segmentB->hd;

	const size_t resp_buf_size = 1024;
	size_t resp_buf_used = 0;
	resp_buf = malloc(resp_buf_size);
	if (resp_buf == NULL) {
		ret = WBCRYPTO_ERR_WBSM2_ALLOC_FAILED;
		goto cleanup;
	}

	MBEDTLS_MPI_CHK(wbcrypto_sm2coop_decrypt_server_respond(
		&wrap_ctx,
		decrypt_ctx->req_buf, decrypt_ctx->req_size,
		resp_buf, resp_buf_size, &resp_buf_used,
		f_rng, p_rng
	));

	decrypt_ctx->resp_buf = resp_buf;
	resp_buf = NULL;
	decrypt_ctx->resp_size = resp_buf_used;
	
cleanup:
	free(resp_buf);
	return ret;
}

int wbcrypto_wbsm2_decrypt_complete(
	wbcrypto_wbsm2_public_key* public_key,
	wbcrypto_wbsm2_private_key_segment* segmentA,
	wbcrypto_wbsm2_decrypt_session* decrypt_ctx,
	const unsigned char* ciphertext, size_t clen,
	unsigned char* out, size_t max_olen, size_t* olen
) {
	int ret = 0;
	wbcrypto_sm2coop_context wrap_ctx;
	wbcrypto_sm2coop_decrypt_client_session wrap_decrypt_ctx;

	WBSM2_VALIDATE_RET(public_key != NULL);
	WBSM2_VALIDATE_RET(segmentA != NULL);
	WBSM2_VALIDATE_RET(decrypt_ctx != NULL);
	WBSM2_VALIDATE_RET(ciphertext != NULL);
	WBSM2_VALIDATE_RET(clen > 0);
	WBSM2_VALIDATE_RET(out != NULL);
	WBSM2_VALIDATE_RET(max_olen > 0);
	WBSM2_VALIDATE_RET(olen != NULL);

	wrap_ctx.grp = public_key->grp;
	wrap_ctx.P = public_key->P;
	wrap_ctx.W = segmentA->W;
	wrap_ctx.hd = segmentA->hd;

	wrap_decrypt_ctx.total_size = decrypt_ctx->total_size;
	wrap_decrypt_ctx.c1point = decrypt_ctx->c1point;
	wrap_decrypt_ctx.c2_offset = decrypt_ctx->c2_offset;
	wrap_decrypt_ctx.c2_len = decrypt_ctx->c2_len;
	wrap_decrypt_ctx.c3_offset = decrypt_ctx->c3_offset;
	wrap_decrypt_ctx.c3_len = decrypt_ctx->c3_len;

	MBEDTLS_MPI_CHK(wbcrypto_sm2coop_decrypt_client_complete(
		&wrap_ctx,
		&wrap_decrypt_ctx,
		decrypt_ctx->resp_buf, decrypt_ctx->resp_size,
		ciphertext, clen,
		out, max_olen, olen
	));

cleanup:
	return ret;
}


void wbcrypto_wbsm2_sign_session_init(wbcrypto_wbsm2_sign_session* ctx) {
	mbedtls_mpi_init(&ctx->k);
	ctx->req_buf = NULL;
	ctx->req_size = 0;
	ctx->dgst_buf = NULL;
	ctx->dgst_size = 0;
	ctx->resp_buf = NULL;
	ctx->resp_size = 0;
}

int wbcrypto_wbsm2_sign_session_copy(
	wbcrypto_wbsm2_sign_session* dst,
	const wbcrypto_wbsm2_sign_session* src
) {
	int ret = 0;
	if (dst == NULL || src == NULL) {
		return WBCRYPTO_ERR_SM2COOP_BAD_INPUT_DATA;
	}

	MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&dst->k, &src->k));
	MBEDTLS_MPI_CHK(buffer_copy(&dst->req_buf, &dst->req_size, src->req_buf, src->req_size));
	MBEDTLS_MPI_CHK(buffer_copy(&dst->dgst_buf, &dst->dgst_size, src->dgst_buf, src->dgst_size));
	MBEDTLS_MPI_CHK(buffer_copy(&dst->resp_buf, &dst->resp_size, src->resp_buf, src->resp_size));

cleanup:
	return ret;
}

void wbcrypto_wbsm2_sign_session_free(wbcrypto_wbsm2_sign_session* ctx) {
	if(ctx!= NULL) {
		mbedtls_mpi_free(&ctx->k);
		free(ctx->req_buf);
		free(ctx->resp_buf);
		free(ctx->dgst_buf);
	}
}


int wbcrypto_wbsm2_sign_stepA(
	wbcrypto_wbsm2_public_key* pubkey,
	wbcrypto_wbsm2_private_key_segment* segmentA,
	wbcrypto_wbsm2_sign_session* sign_ctx,
	const unsigned char* msg, size_t msglen,
	int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
) {
	return wbcrypto_wbsm2_sign_stepA_withID(
		pubkey,
		segmentA,
		sign_ctx,
		sm2_default_id, sm2_default_id_length,
		msg, msglen,
		f_rng, p_rng
	);
}

int wbcrypto_wbsm2_sign_stepA_withID(
	wbcrypto_wbsm2_public_key* pubkey, 
	wbcrypto_wbsm2_private_key_segment* segmentA, 
	wbcrypto_wbsm2_sign_session* sign_ctx, 
	const char* id, size_t idlen, 
	const unsigned char* msg, size_t msglen, 
	int (* f_rng)(void*, unsigned char*, size_t), void* p_rng
) {
	int ret = 0;
	wbcrypto_sm2coop_context wrap_ctx;
	wbcrypto_sm2coop_sign_client_session wrap_sign_ctx;
	uint8_t* req_buf = NULL;
	uint8_t* dgst_buf = NULL;

	WBSM2_VALIDATE_RET(pubkey != NULL);
	WBSM2_VALIDATE_RET(segmentA != NULL);
	WBSM2_VALIDATE_RET(sign_ctx != NULL);
	WBSM2_VALIDATE_RET(id != NULL);
	WBSM2_VALIDATE_RET(idlen > 0);
	WBSM2_VALIDATE_RET(msg != NULL);
	WBSM2_VALIDATE_RET(msglen > 0);
	WBSM2_VALIDATE_RET(f_rng != NULL);
	
	wrap_ctx.grp = pubkey->grp;
	wrap_ctx.P = pubkey->P;
	wrap_ctx.W = segmentA->W;
	wrap_ctx.hd = segmentA->hd;

	wbcrypto_sm2coop_sign_client_session_init(&wrap_sign_ctx);

	size_t req_buf_size = 1024;
	req_buf = malloc(req_buf_size);
	size_t req_used = 0;

	size_t dgst_buf_size = 1024;
	dgst_buf = malloc(dgst_buf_size);
	size_t dgst_used = 0;
	
	if (req_buf == NULL) {
		ret = WBCRYPTO_ERR_SM2COOP_ALLOC_FAILED;
		goto cleanup;
	}
	if (dgst_buf == NULL) {
		ret = WBCRYPTO_ERR_SM2COOP_ALLOC_FAILED;
		goto cleanup;
	}

	MBEDTLS_MPI_CHK(
		wbcrypto_sm2coop_sign_client_start_withID(
			&wrap_ctx,
			&wrap_sign_ctx,
			(unsigned char*)id, idlen,
			msg, msglen,
			dgst_buf, dgst_buf_size, &dgst_used,
			req_buf, req_buf_size, &req_used,
			f_rng, p_rng
		)
	);

	sign_ctx->k = wrap_sign_ctx.k;

	sign_ctx->req_buf = req_buf;
	req_buf = NULL;
	sign_ctx->req_size = req_used;

	sign_ctx->dgst_buf = dgst_buf;
	dgst_buf = NULL;
	sign_ctx->dgst_size = dgst_used;

cleanup:
	free(req_buf);
	free(dgst_buf);
	return ret;
}

int wbcrypto_wbsm2_sign_stepB(
	wbcrypto_wbsm2_public_key* pubkey,
	wbcrypto_wbsm2_private_key_segment* segmentB,
	wbcrypto_wbsm2_sign_session* sign_ctx,
	int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
) {
	int ret = 0;
	wbcrypto_sm2coop_context wrap_ctx;
	uint8_t* resp_buf = NULL;
	
	WBSM2_VALIDATE_RET(pubkey != NULL);
	WBSM2_VALIDATE_RET(segmentB != NULL);
	WBSM2_VALIDATE_RET(sign_ctx != NULL);
	WBSM2_VALIDATE_RET(f_rng != NULL);

	wrap_ctx.grp = pubkey->grp;
	wrap_ctx.P = pubkey->P;
	wrap_ctx.W = segmentB->W;
	wrap_ctx.hd = segmentB->hd;

	size_t resp_buf_size = 1024;
	resp_buf = malloc(resp_buf_size);
	size_t resp_used = 0;
	if (resp_buf == NULL) {
		ret = WBCRYPTO_ERR_SM2COOP_ALLOC_FAILED;
		goto cleanup;
	}

	MBEDTLS_MPI_CHK(
		wbcrypto_sm2coop_sign_server_respond(
			&wrap_ctx,
			sign_ctx->dgst_buf, sign_ctx->dgst_size,
			sign_ctx->req_buf, sign_ctx->req_size,
			resp_buf, resp_buf_size, &resp_used,
			f_rng, p_rng
		)
	);

	sign_ctx->resp_buf = resp_buf;
	resp_buf = NULL;
	sign_ctx->resp_size = resp_used;

cleanup:
	free(resp_buf);
	return ret;
}

int wbcrypto_wbsm2_sign_complete(
	wbcrypto_wbsm2_public_key* pubkey,
	wbcrypto_wbsm2_private_key_segment* segmentA,
	wbcrypto_wbsm2_sign_session* sign_ctx,
	unsigned char* sig, size_t max_siglen, size_t* siglen
) {
	int ret = 0;
	wbcrypto_sm2coop_context wrap_ctx;
	wbcrypto_sm2coop_sign_client_session wrap_sign_ctx;

	WBSM2_VALIDATE_RET(pubkey != NULL);
	WBSM2_VALIDATE_RET(segmentA != NULL);
	WBSM2_VALIDATE_RET(sign_ctx != NULL);
	WBSM2_VALIDATE_RET(sig != NULL);
	WBSM2_VALIDATE_RET(max_siglen > 0);
	WBSM2_VALIDATE_RET(siglen > 0);

	wrap_ctx.grp = pubkey->grp;
	wrap_ctx.P = pubkey->P;
	wrap_ctx.W = segmentA->W;
	wrap_ctx.hd = segmentA->hd;

	wrap_sign_ctx.k = sign_ctx->k;

	MBEDTLS_MPI_CHK(
		wbcrypto_sm2coop_sign_client_complete(
			&wrap_ctx,
			&wrap_sign_ctx,
			sign_ctx->resp_buf, sign_ctx->resp_size,
			sig, max_siglen, siglen
		)
	);

cleanup:
	return ret;
}

int wbcrypto_wbsm2_verify(
	wbcrypto_wbsm2_public_key* pubkey,
	const unsigned char* message, size_t msglen,
	const unsigned char* sig, size_t siglen
) {
	int ret = 0;
	wbcrypto_sm2coop_context wrap_ctx;

	WBSM2_VALIDATE_RET(pubkey != NULL);
	WBSM2_VALIDATE_RET(message != NULL);
	WBSM2_VALIDATE_RET(msglen > 0);
	WBSM2_VALIDATE_RET(sig != NULL);
	WBSM2_VALIDATE_RET(siglen > 0);
	
	wrap_ctx.grp = pubkey->grp;
	wrap_ctx.P = pubkey->P;

	int ret2 = (
		wbcrypto_sm2coop_verify(
			&wrap_ctx,
			message, msglen,
			sig, siglen
		)
	);
	
	switch (ret2) {
		case WBCRYPTO_ERR_SM2COOP_VERIFY_FAILED:
			THROW(WBCRYPTO_ERR_WBSM2_VERIFY_FAILED);
		default:
			THROW(ret2);
	}
	
cleanup:
	return ret;
}

int wbcrypto_wbsm2_verify_withID(
	wbcrypto_wbsm2_public_key* pubkey,
	const unsigned char* id, size_t idlen,
	const unsigned char* msg, size_t msglen,
	const unsigned char* sig, size_t siglen
) {
	int ret = 0;
	wbcrypto_sm2coop_context wrap_ctx;

	WBSM2_VALIDATE_RET(pubkey != NULL);
	WBSM2_VALIDATE_RET(id != NULL);
	WBSM2_VALIDATE_RET(idlen > 0);
	WBSM2_VALIDATE_RET(msg != NULL);
	WBSM2_VALIDATE_RET(msglen > 0);
	WBSM2_VALIDATE_RET(sig != NULL);
	WBSM2_VALIDATE_RET(siglen > 0);
	
	wrap_ctx.grp = pubkey->grp;
	wrap_ctx.P = pubkey->P;

	int ret2 = (
		wbcrypto_sm2coop_verify_withID(
			&wrap_ctx,
			id, idlen,
			msg, msglen,
			sig, siglen
		)
	);

	switch (ret2) {
		case WBCRYPTO_ERR_SM2COOP_VERIFY_FAILED:
			THROW(WBCRYPTO_ERR_WBSM2_VERIFY_FAILED);
		default:
			THROW(ret2);
	}

cleanup:
	return ret;
}
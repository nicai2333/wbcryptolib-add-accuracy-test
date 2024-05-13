#include <stdlib.h>
#include <memory.h>
#include "mbedtls/asn1write.h"
#include "mbedtls/asn1.h"
#include "crypto/sm2.h"
#include "crypto/sm3.h"
#include "wbcrypto/internal/asn1_utils.h"
#include "wbcrypto/internal/sm2/sm2_utils.h"

#define SM2_SIGINT_LENGTH 32

int wbcrypto_sm2_context_init(wbcrypto_sm2_context* ctx) {
	memset(ctx, 0, sizeof(wbcrypto_sm2_context));
	mbedtls_ecp_point_init(&ctx->Pb);
	mbedtls_mpi_init(&ctx->d);
	return wbcrypto_sm2_load_default_group(&(ctx->grp));
}

int wbcrypto_sm2_context_copy(wbcrypto_sm2_context* dst, const wbcrypto_sm2_context* src) {
	int ret;
	MBEDTLS_MPI_CHK(mbedtls_ecp_group_copy(&dst->grp, &src->grp));
	MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&dst->d, &src->d));
	MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&dst->Pb.X, &src->Pb.X));
	MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&dst->Pb.Y, &src->Pb.Y));
	MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&dst->Pb.Z, &src->Pb.Z));
cleanup:
	return (ret);
}

void wbcrypto_sm2_context_free(wbcrypto_sm2_context* ctx) {
	if (ctx != NULL) {
		mbedtls_ecp_group_free(&ctx->grp);
		mbedtls_ecp_point_free(&ctx->Pb);
		mbedtls_mpi_free(&ctx->d);
	}
}


int wbcrypto_sm2_gen_keypair(
	wbcrypto_sm2_context* ctx,
	int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
) {
	return mbedtls_ecp_gen_keypair(
		&(ctx->grp), &(ctx->d), &(ctx->Pb), 
		f_rng, p_rng
	);
}

int wbcrypto_sm2_check_privkey(wbcrypto_sm2_context* ctx) {
	return mbedtls_ecp_check_privkey(&(ctx->grp), &(ctx->d));
}

int wbcrypto_sm2_check_pubkey(wbcrypto_sm2_context* ctx) {
	return mbedtls_ecp_check_pubkey(&(ctx->grp), &(ctx->Pb));
}


/**
* internal function for SM2 encryption
* will operate as public API,but put result separatly into c1point, c2, c3
* c1point is the point to be written into c1 part
* c2 is assumed to be of size blen
* c3 is assumed to be of size SM3_DIGEST_LENGTH
*/
static int wbcrypto_sm2_encrypt_internal(
	wbcrypto_sm2_context* ctx,
	const unsigned char* buffer, size_t	blen,	
	mbedtls_ecp_point* c1point,
	unsigned char* c2_buf,
	unsigned char* c3_buf,
	int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
) {
	int ret;

	size_t max_len = blen + 64 * 2 + 1;

	size_t temp_len = max_len;
	unsigned char* temp = calloc(temp_len, sizeof(unsigned char));

	if (temp == NULL) {
		free(temp);
		return MBEDTLS_ERR_MPI_ALLOC_FAILED;
	}

	mbedtls_mpi k;
	mbedtls_ecp_point KPb;

	mbedtls_mpi_init(&k);
	mbedtls_ecp_point_init(&KPb);

	do {
		/* generate rand k in [1, n-1] */
		size_t n_size = (ctx->grp.nbits + 7) / 8;
		MBEDTLS_MPI_CHK(mbedtls_mpi_fill_random(&k, n_size, f_rng, p_rng));
		MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&k, &k, &ctx->grp.N));

		/* compute [k]G = (x1, y1) into KG */
		MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&(ctx->grp), c1point, &k, &(ctx->grp.G), NULL, NULL));

		/* compute [k]P_B into KPb */
		MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&(ctx->grp), &KPb, &k, &(ctx->Pb), NULL, NULL));

		/* write KPb(x2,y2) into temp = x2 || y2*/
		MBEDTLS_MPI_CHK(write_point_x_y(&(ctx->grp), &KPb, temp, &temp_len));

		/* compute t = KDF(x2 || y2, klen) */
		MBEDTLS_MPI_CHK(kdf(c2_buf, temp, temp_len, blen));
		temp_len = max_len;

		// check :if(t == 0) -> return to 1st step
		int iter = 0;
		for (iter = 0; iter < blen; iter++) {
			if (c2_buf[iter] != 0)
				break;
		}
		if (blen != iter) {
			break;
		}

	} while (1);

	/* compute C2 = t xor M */
	int i;
	for (i = 0; i < blen; i++) {
		c2_buf[i] ^= buffer[i];
	}

	/*compute C3 = HASH(x2|| M || y2)*/
	/*temp buf = x2 || m || y2*/
	MBEDTLS_MPI_CHK(write_x2_m_y2(&(ctx->grp), &KPb, buffer, blen, temp, &temp_len));
	wbcrypto_sm3(temp, temp_len, c3_buf);

cleanup:
	mbedtls_mpi_free(&k);
	mbedtls_ecp_point_free(&KPb);
	free(temp);
	return (ret);
}


/**
* internal function for SM2 decryption
* will operate as public API,but read result separatly into c1point, c2, c3
* c1point is the point of c1 part
* c2 is assumed to be of size c2_len
* c3 is assumed to be of size SM3_DIGEST_LENGTH
*/
static int wbcrypto_sm2_decrypt_internal(
	wbcrypto_sm2_context* ctx,
	mbedtls_ecp_point* c1point,
	unsigned char* c2_buf, size_t c2_len,
	unsigned char* c3_buf,
	unsigned char* out, size_t max_olen, size_t* olen
) {
	int ret;
	
	unsigned char c3_expected_buf[SM3_DIGEST_LENGTH];

	//unknown reason, why we need to have the presumed c1+c2+c3 length?
	size_t temp_len = mbedtls_mpi_size(&ctx->grp.P)*2 + c2_len + SM3_DIGEST_LENGTH; 
	unsigned char* temp = calloc(temp_len, sizeof(unsigned char));
	unsigned char* temp2 = calloc(temp_len, sizeof(unsigned char));

	if (temp == NULL || temp2 == NULL) {
		free(temp);
		free(temp2);
		return WBCRYPTO_ERR_SM2_ALLOC_FAILED;
	}

	mbedtls_ecp_point P_2;
	mbedtls_ecp_point_init(&P_2);

	/*get c1 point x1,y1  to P_1*/
	/* check c1 */
	MBEDTLS_MPI_CHK(mbedtls_ecp_check_pubkey(&(ctx->grp), c1point));

	/* P_2 = dA*C1 = (x2,y2) */
	MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&(ctx->grp), &P_2, &(ctx->d), c1point, NULL, NULL));

	/* t= KDF(x2||y2, klen)*/
	/*temp =  x2 || y2 */
	MBEDTLS_MPI_CHK(write_point_x_y(&(ctx->grp), &P_2, temp, &temp_len));

	/* compute t = KDF(x2 || y2, klen) */
	MBEDTLS_MPI_CHK(kdf(temp2, temp, temp_len, c2_len));

	/*check  t !=0;*/
	int i;
	for (i = 0; i < c2_len; i++) {
		if (temp2[i] != 0)
			break;
	}
	if ((int)c2_len == i) {
		ret = WBCRYPTO_ERR_SM2_BAD_INPUT_DATA;
		goto cleanup;
	}

	/* m` = t xor c2 */
	for (i = 0; i < c2_len; i++) {
		c2_buf[i] ^= temp2[i];
	}

	/*compute u = HASH(x2|| M` || y2)*/
	/*temp buf = x2 || m` || y2*/
	MBEDTLS_MPI_CHK(write_x2_m_y2(&(ctx->grp), &P_2, c2_buf, c2_len, temp, &temp_len));

	wbcrypto_sm3(temp, temp_len, c3_expected_buf);

	for (i = 0; i < SM3_DIGEST_LENGTH; i++) {
		if (c3_buf[i] != c3_expected_buf[i]) {
			ret = WBCRYPTO_ERR_SM2_PRIVATE_FAILED;
			goto cleanup;
		}
	}

	if (max_olen < c2_len || NULL == out) {
		ret = WBCRYPTO_ERR_SM2_OUTPUT_TOO_LARGE;
		goto cleanup;
	}

	memset(out, 0, max_olen);
	memcpy(out, c2_buf, c2_len);

cleanup:
	free(temp);
	free(temp2);
	*olen = c2_len;
	mbedtls_ecp_point_free(&P_2);
	return (ret);
}


/**
* internal function for SM2 signing
* will operate as public API,but write result separatly into r & s
*/
static int wbcrypto_sm2_sign_withID_internal(
	wbcrypto_sm2_context* ctx,
	const unsigned char* id, size_t idlen,
	const unsigned char* msg, size_t msglen,
	mbedtls_mpi* r, mbedtls_mpi* s,
	int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
) {
	int ret;
	mbedtls_mpi e;
	mbedtls_mpi k;
	mbedtls_mpi tmp;
	mbedtls_mpi tmp_2;

	mbedtls_ecp_point KG;

	unsigned char hashedMbar[SM3_DIGEST_LENGTH];

	mbedtls_mpi_init(&e);
	mbedtls_mpi_init(&k);
	mbedtls_mpi_init(&tmp);
	mbedtls_mpi_init(&tmp_2);

	mbedtls_ecp_point_init(&KG);

	/* compute digest */
	MBEDTLS_MPI_CHK(wbcrypto_sm2_compute_hashedMbar(
		ctx,
		id, idlen,
		msg, msglen,
		hashedMbar
	));
	/* convert dgst to e  : e = h(m)  */
	MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&e, hashedMbar, SM3_DIGEST_LENGTH));

	do {
		/* generate rand k  from range n*/
		size_t n_size = (ctx->grp.nbits + 7) / 8;
		MBEDTLS_MPI_CHK(mbedtls_mpi_fill_random(&k, n_size, f_rng, p_rng));
		MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&k, &k, &ctx->grp.N));

		/*KG = [K]G = (x1,y1)*/
		MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&(ctx->grp), &KG, &k, &(ctx->grp.G), NULL, NULL));

		/*r = (e + x1) mod n*/
		/* tmp = e + x1 */
		MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&tmp, &e, &KG.X));
		MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(r, &tmp, &(ctx->grp.N)));

		/* r !=0 and r + k != n*/
		if (mbedtls_mpi_cmp_int(r, 0) == 0) {
			continue;
		}
		else {
			mbedtls_mpi_free(&tmp);
			MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&tmp, r, &k));
			if (mbedtls_mpi_cmp_mpi(&tmp, &(ctx->grp.N)) == 0) {
				continue;
			}
		}

		/* s = ((1 + d)^-1 * (k - rd)) mod n
		 * s = (((1 + d)^-1 mod n) *  ((k - rd) mod n) ) mod n
		 */
		 /*((1 + d)^-1 mod n)*/
		mbedtls_mpi_free(&tmp);
		MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&tmp, &ctx->d, 1));
		MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(s, &tmp, &(ctx->grp.N)));

		/* ((k - rd) mod n) */
		/* tmp = rd */
		mbedtls_mpi_init(&tmp);
		MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&tmp, r, (&ctx->d)));
		/* tmp_2 = k - rd */
		MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&tmp_2, &k, &tmp));
		/* tmp_2 mod n*/
		mbedtls_mpi_free(&tmp);
		MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tmp, &tmp_2, &(ctx->grp.N)));

		/* tmp_2 = ((1 + d)^-1 mod n) *  ((k - rd) mod n) */
		mbedtls_mpi_free(&tmp_2);
		MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&tmp_2, s, &tmp));
		/* s = tmp_2 mod n*/
		mbedtls_mpi_free(s);
		MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(s, &tmp_2, &(ctx->grp.N)));

		if (mbedtls_mpi_cmp_int(s, 0) == 0) {
			continue;
		}
		else {
			break;
		}

	} while (1);

cleanup:
	mbedtls_mpi_free(&e);
	mbedtls_mpi_free(&k);
	mbedtls_mpi_free(&tmp);
	mbedtls_mpi_free(&tmp_2);
	mbedtls_ecp_point_free(&KG);
	return (ret);
}


/**
* internal function for SM2 verify
* will operate as public API,but load signature from r & s
*/
static int wbcrypto_sm2_verify_withID_internal(
	wbcrypto_sm2_context* ctx,
	const char* id, size_t idlen,
	const char* message, size_t msglen,
	mbedtls_mpi* r, mbedtls_mpi* s
) {

	int ret;
	mbedtls_mpi t;
	mbedtls_mpi tmp;

	mbedtls_ecp_point pointG;
	char hashedMbar[SM3_DIGEST_LENGTH];

	mbedtls_mpi_init(&t);
	mbedtls_mpi_init(&tmp);

	mbedtls_ecp_point_init(&pointG);

	/* check r, s in [1, n-1]*/
	if (mbedtls_mpi_cmp_int(r, 1) == -1 || mbedtls_mpi_cmp_int(s, 1) == -1
		|| mbedtls_mpi_cmp_mpi(r, &(ctx->grp.N)) == 1
		|| mbedtls_mpi_cmp_mpi(s, &(ctx->grp.N)) == 1) {
		ret = WBCRYPTO_ERR_SM2_BAD_INPUT_DATA;
		goto cleanup;
	}

	/*  t = (r + s) mod n  */
	/* tmp = r + s*/
	MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&tmp, r, s));
	MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&t, &tmp, &(ctx->grp.N)));

	/* check t  != 0 */
	if (mbedtls_mpi_cmp_int(&t, 0) == 0) {
		ret = WBCRYPTO_ERR_SM2_BAD_INPUT_DATA;
		goto cleanup;
	}

	/* compute pointG= (x, y) = sG + tP, P is pub_key */
	MBEDTLS_MPI_CHK(mbedtls_ecp_muladd(&(ctx->grp), &pointG, s, &(ctx->grp.G), &t, &(ctx->Pb)));

	/* tmp <- R = (e + x1) mod n  ;x1 in pointG */
	/* compute e */
	MBEDTLS_MPI_CHK(wbcrypto_sm2_compute_hashedMbar(ctx,
		id, idlen,
		message, msglen,
		hashedMbar
	));
	mbedtls_mpi_free(&t);
	MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&t, hashedMbar, SM3_DIGEST_LENGTH));
	/* s <- e + x1 */
	mbedtls_mpi_free(s);
	MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(s, &t, &(pointG.X)));
	/*tmp <- R = s mod n*/
	mbedtls_mpi_free(&tmp);
	MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tmp, s, &(ctx->grp.N)));

	/*tmp (R) = r ?*/
	if (mbedtls_mpi_cmp_mpi(&tmp, r) != 0) {
		ret = WBCRYPTO_ERR_SM2_VERIFY_FAILED;
	}

cleanup:

	mbedtls_mpi_free(&t);
	mbedtls_mpi_free(&tmp);

	mbedtls_ecp_point_free(&pointG);
	return (ret);
}




int wbcrypto_sm2_encrypt_rawBytes(
	wbcrypto_sm2_context* ctx,
	const unsigned char* buffer, size_t	blen,
	unsigned char* out, size_t max_olen, size_t* olen,
	int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
) {
	int ret;

	mbedtls_ecp_point c1point;
	mbedtls_ecp_point_init(&c1point);

	size_t c1_len = mbedtls_mpi_size(&ctx->grp.P) * 2 + 1, c2_len = blen, c3_len = SM3_DIGEST_LENGTH;
	size_t result_buflen = c1_len + c2_len + c3_len;

	if (ctx == NULL || buffer == NULL) {
		return WBCRYPTO_ERR_SM2_BAD_INPUT_DATA;
	}

	if (max_olen < result_buflen || NULL == out) {
		ret = WBCRYPTO_ERR_SM2_OUTPUT_TOO_LARGE;
		goto cleanup;
	}

	MBEDTLS_MPI_CHK(wbcrypto_sm2_encrypt_internal(
		ctx,
		buffer, blen,
		&c1point, out + c1_len, out + c1_len + c2_len,
		f_rng, p_rng
	));

	/* write KG as C1 */
	memset(out, 0, c1_len);
	size_t tmp = 0;
	MBEDTLS_MPI_CHK(mbedtls_ecp_point_write_binary(
		&(ctx->grp), &c1point, MBEDTLS_ECP_PF_UNCOMPRESSED, &tmp, out, c1_len)
	);


cleanup: 
	*olen = result_buflen;
	mbedtls_ecp_point_free(&c1point);
	return (ret);
}


int wbcrypto_sm2_decrypt_rawBytes(
	wbcrypto_sm2_context* ctx,
	const unsigned char* ciphertext, size_t clen,
	unsigned char* out, size_t max_olen, size_t* olen
) {
	int ret;
	
	mbedtls_ecp_point c1point;
	mbedtls_ecp_point_init(&c1point);

	//assumed section sizes
	size_t c1_len = mbedtls_mpi_size(&ctx->grp.P) * 2 + 1;
	size_t c3_len = SM3_DIGEST_LENGTH;
	size_t c2_len = clen - c1_len - c3_len;

	if (NULL == ciphertext || c1_len + SM3_DIGEST_LENGTH >= clen) {
		return WBCRYPTO_ERR_SM2_BAD_INPUT_DATA;
	}

	MBEDTLS_MPI_CHK(mbedtls_ecp_point_read_binary(&(ctx->grp), &c1point, ciphertext, c1_len));
	MBEDTLS_MPI_CHK(wbcrypto_sm2_decrypt_internal(
		ctx,
		&c1point,
		ciphertext + c1_len, c2_len,
		ciphertext + c1_len + c2_len,
		out, max_olen, olen
	));
	
cleanup: 
	*olen = c2_len;
	mbedtls_ecp_point_free(&c1point);
	return (ret);
}


int wbcrypto_sm2_sign_rawBytes(
	wbcrypto_sm2_context* ctx,
	const unsigned char* msg, size_t msglen,
	unsigned char* out, size_t max_olen, size_t* olen,
	int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
) {
	return wbcrypto_sm2_sign_withID_rawBytes(
		ctx,
		sm2_default_id, sm2_default_id_length,
		msg, msglen,
		out, max_olen, olen,
		f_rng, p_rng
	);
}


int wbcrypto_sm2_verify_rawBytes(
	wbcrypto_sm2_context* ctx,
	const unsigned char* message, size_t msglen,
	const unsigned char* sig, size_t siglen
) {
	return wbcrypto_sm2_verify_withID_rawBytes(
		ctx,
		sm2_default_id, sm2_default_id_length,
		message, msglen,
		sig, siglen
	);
}


int wbcrypto_sm2_sign_withID_rawBytes(
	wbcrypto_sm2_context* ctx,
	const char* id, size_t idlen,
	const char* msg, size_t msglen,
	unsigned char* out, size_t max_olen, size_t* olen,
	int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
) {
	int ret;
	mbedtls_mpi r;
	mbedtls_mpi s;
	
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	MBEDTLS_MPI_CHK(wbcrypto_sm2_sign_withID_internal(
		ctx,
		id, idlen,
		msg, msglen,
		&r, &s,
		f_rng, p_rng
	));

	if(max_olen < SM2_SIGINT_LENGTH * 2) {
		return WBCRYPTO_ERR_SM2_OUTPUT_TOO_LARGE;
	}

	*olen = SM2_SIGINT_LENGTH * 2;
	MBEDTLS_MPI_CHK(write_x_y(SM2_SIGINT_LENGTH, &r, &s, out, olen));

cleanup:
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
	return (ret);
}


int wbcrypto_sm2_verify_withID_rawBytes(
	wbcrypto_sm2_context* ctx,
	const char* id, size_t idlen,
	const char* message, size_t msglen,
	const unsigned char* sig, size_t siglen
) {
	int ret;
	mbedtls_mpi r;
	mbedtls_mpi s;

	if (siglen < SM2_SIGINT_LENGTH * 2) {
		return WBCRYPTO_ERR_SM2_BAD_INPUT_DATA;
	}

	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	/*init r and s from byte*/
	mbedtls_mpi_read_binary(&r, sig, SM2_SIGINT_LENGTH);
	mbedtls_mpi_read_binary(&s, sig + SM2_SIGINT_LENGTH, SM2_SIGINT_LENGTH);

	MBEDTLS_MPI_CHK(wbcrypto_sm2_verify_withID_internal(
		ctx,
		id, idlen,
		message, msglen,
		&r, &s
	));

cleanup:
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
	return (ret);
}


int wbcrypto_sm2_encrypt_asn1(
	wbcrypto_sm2_context* ctx,
	const unsigned char* buffer, size_t	blen,
	unsigned char* out, size_t max_olen, size_t* olen,
	int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
) {
	int ret = 0;
	mbedtls_ecp_point c1point;
	unsigned char* c2 = NULL, *c3 = NULL;
	mbedtls_ecp_point_init(&c1point);
	c2 = calloc(blen,sizeof(unsigned char));
	c3 = calloc(SM3_DIGEST_LENGTH, sizeof(unsigned char));
	if(c2 == NULL || c3 == NULL) {
		ret = WBCRYPTO_ERR_SM2_ALLOC_FAILED;
		goto cleanup;
	}

	MBEDTLS_MPI_CHK(wbcrypto_sm2_encrypt_internal(
		ctx,
		buffer, blen,
		&c1point,
		c2,
		c3,
		f_rng, p_rng
	));

	//data offset to fill hex data into and their size

	//full size, aka tag+length+content
	size_t c1_full_size = wbcrypto_asn1_mpi_buflength(&c1point.X) + wbcrypto_asn1_mpi_buflength(&c1point.Y);
	size_t c1_offset = 0;

	size_t c3_data_size = 32;
	size_t c3_offset =
		c1_full_size
		+ WBCRYPTO_ASN1_TAG_BUFLENGTH
		+ wbcrypto_asn1_len_buflength(c3_data_size)
		;

	size_t c2_data_size = blen;
	size_t c2_offset =
		c3_offset
		+ c3_data_size
		+ WBCRYPTO_ASN1_TAG_BUFLENGTH
		+ wbcrypto_asn1_len_buflength(c2_data_size)
		;

	size_t sequence_size = c2_offset + c2_data_size;

	size_t output_size =
		WBCRYPTO_ASN1_TAG_BUFLENGTH
		+ wbcrypto_asn1_len_buflength(sequence_size)
		+ sequence_size
		;

	if (output_size > max_olen) {
		return WBCRYPTO_ERR_SM2_OUTPUT_TOO_LARGE;
	}

	*olen = output_size;
	unsigned char* p = out + output_size;
	memcpy(p - c2_data_size, c2, c2_data_size);
	p -= c2_data_size;
	WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_len(&p, out, c2_data_size));
	WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_tag(&p, out, MBEDTLS_ASN1_OCTET_STRING));
	memcpy(p - c3_data_size, c3, c3_data_size);
	p -= c3_data_size;
	WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_len(&p, out, c3_data_size));
	WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_tag(&p, out, MBEDTLS_ASN1_OCTET_STRING));
	WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_mpi(&p, out, &c1point.Y));
	WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_mpi(&p, out, &c1point.X));
	WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_len(&p, out, sequence_size));
	WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_tag(&p, out, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
	ret = 0;//asn1 writer have pos return value on success
cleanup:
	free(c2);
	free(c3);
	mbedtls_ecp_point_free(&c1point);
	return (ret);
}


int wbcrypto_sm2_decrypt_asn1(
	wbcrypto_sm2_context* ctx,
	const unsigned char* ciphertext, size_t clen,
	unsigned char* out, size_t max_olen, size_t* olen
) {
	int ret = 0;
	
	mbedtls_ecp_point c1point;
	mbedtls_ecp_point_init(&c1point);

	unsigned char* now = ciphertext, * end = ciphertext + clen;
	size_t body_length = 0;
	unsigned char *c2 = 0, *c3 = 0;
	size_t c2_size = 0, c3_size = 0;
	
	/*read input*/
	MBEDTLS_MPI_CHK(mbedtls_asn1_get_tag(&now, end, &body_length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
	MBEDTLS_MPI_CHK(mbedtls_asn1_get_mpi(&now, end, &c1point.X));
	MBEDTLS_MPI_CHK(mbedtls_asn1_get_mpi(&now, end, &c1point.Y));
	MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&c1point.Z, 1));
	MBEDTLS_MPI_CHK(mbedtls_asn1_get_tag(&now, end, &c3_size, MBEDTLS_ASN1_OCTET_STRING));
	c3 = now;
	now += c3_size;
	MBEDTLS_MPI_CHK(mbedtls_asn1_get_tag(&now, end, &c2_size, MBEDTLS_ASN1_OCTET_STRING));
	c2 = now;
	now += c2_size;

	MBEDTLS_MPI_CHK(wbcrypto_sm2_decrypt_internal(
		ctx,
		&c1point,
		c2, c2_size, 
		c3, 
		out, max_olen, olen
	));

cleanup:
	mbedtls_ecp_point_free(&c1point);
	return (ret);
}


int wbcrypto_sm2_sign_asn1(
	wbcrypto_sm2_context* ctx,
	const unsigned char* msg, size_t msglen,
	unsigned char* out, size_t max_olen, size_t* olen,
	int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
) {
	return wbcrypto_sm2_sign_withID_asn1(
		ctx,
		sm2_default_id, sm2_default_id_length,
		msg, msglen,
		out, max_olen, olen,
		f_rng, p_rng
	);
}


int wbcrypto_sm2_verify_asn1(
	wbcrypto_sm2_context* ctx,
	const unsigned char* message, size_t msglen,
	const unsigned char* sig, size_t siglen
) {
	return wbcrypto_sm2_verify_withID_asn1(
		ctx,
		sm2_default_id, sm2_default_id_length,
		message, msglen,
		sig, siglen
	);
}


int wbcrypto_sm2_sign_withID_asn1(
	wbcrypto_sm2_context* ctx,
	const char* id, size_t idlen,
	const char* msg, size_t msglen,
	unsigned char* out, size_t max_olen, size_t* olen,
	int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
) {
	int ret = 0;
	mbedtls_mpi r;
	mbedtls_mpi s;

	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	MBEDTLS_MPI_CHK(wbcrypto_sm2_sign_withID_internal(
		ctx,
		id, idlen,
		msg, msglen,
		&r, &s,
		f_rng, p_rng
	));

	size_t sequence_body_size =
		wbcrypto_asn1_mpi_buflength(&r)
		+ wbcrypto_asn1_mpi_buflength(&s)
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
	WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_mpi(&p, out, &s));
	WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_mpi(&p, out, &r));
	WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_len(&p, out, sequence_body_size));
	WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_tag(&p, out, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
	ret = 0;//asn1 writer have pos return value on success
cleanup:
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
	return (ret);
}


int wbcrypto_sm2_verify_withID_asn1(
	wbcrypto_sm2_context* ctx,
	const char* id, size_t idlen,
	const char* message, size_t msglen,
	const unsigned char* sig, size_t siglen
) {
	int ret;
	mbedtls_mpi r;
	mbedtls_mpi s;
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	unsigned char *now = sig, *end = sig + siglen;
	int tag_type = 0;
	size_t body_length = 0;
	/*init r and s from byte*/
	MBEDTLS_MPI_CHK(mbedtls_asn1_get_tag(&now, end, &body_length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
	MBEDTLS_MPI_CHK(mbedtls_asn1_get_mpi(&now, end, &r));
	MBEDTLS_MPI_CHK(mbedtls_asn1_get_mpi(&now, end, &s));

	MBEDTLS_MPI_CHK(wbcrypto_sm2_verify_withID_internal(
		ctx,
		id, idlen,
		message, msglen,
		&r, &s
	));

cleanup:
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
	return (ret);
}

#if defined(WBCRYPTO_SELF_TEST)
int wbcrypto_sm2_self_test(int verbose);
#endif
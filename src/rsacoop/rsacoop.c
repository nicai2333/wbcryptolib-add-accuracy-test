#include "wbcrypto/rsacoop.h"
#include "wbcrypto/internal/asn1_utils.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/asn1.h"
#include "mbedtls/oid.h"
#include <memory.h>
#include <stdlib.h>


//IO between mpi r and s and concat of ASN.1 struct
static int write_mpi_pair(const mbedtls_mpi* r, const mbedtls_mpi* s, unsigned char* out, size_t max_olen, size_t* olen);
static int read_mpi_pair(mbedtls_mpi* r, mbedtls_mpi* s, const unsigned char* data, size_t data_len);

//IO of RSACoop sign request
static int write_rsacoop_sign_request(const unsigned char* pkcs15_hash, size_t pkcs15_hash_length, const mbedtls_mpi* r, const mbedtls_mpi* s, unsigned char* out, size_t max_olen, size_t* olen);
static int read_rsacoop_sign_request(unsigned char** pkcs15_hash, size_t* pkcs15_hash_length, mbedtls_mpi* r, mbedtls_mpi* s, const unsigned char* data, size_t data_len);

//IO of RSACoop sign response
static int write_rsacoop_sign_response(const mbedtls_mpi* sigma, unsigned char* out, size_t max_olen, size_t* olen);
static int read_rsacoop_sign_response(mbedtls_mpi* sigma, const unsigned char* data, size_t data_len);

//IO of RSACoop signature
static int write_rsacoop_signature(const mbedtls_mpi* sigma, unsigned char* out, size_t max_olen, size_t* olen);
static int read_rsacoop_signature(mbedtls_mpi* sigma, const unsigned char* data, size_t data_len);


//perform pkcs1_V15 encoding, copied from mbedtls rsa internal
static int rsa_rsassa_pkcs1_v15_encode(
	mbedtls_md_type_t md_alg,
	unsigned int hashlen,
	const unsigned char* hash,
	size_t dst_len,
	unsigned char* dst
);

static int mbedtls_safer_memcmp(const void* a, const void* b, size_t n);

void wbcrypto_rsacoop_client_context_init(wbcrypto_rsacoop_client_context* ctx) {
	mbedtls_rsa_init(&ctx->pk, MBEDTLS_RSA_PKCS_V15, 0);
	mbedtls_mpi_init(&ctx->hd_A);
	mbedtls_mpi_init(&ctx->hd_SA);
	mbedtls_mpi_init(&ctx->n_A);
}

void wbcrypto_rsacoop_client_context_free(wbcrypto_rsacoop_client_context* ctx) {
	if (ctx != NULL) {
		mbedtls_rsa_free(&ctx->pk);
		mbedtls_mpi_free(&ctx->hd_A);
		mbedtls_mpi_free(&ctx->hd_SA);
		mbedtls_mpi_free(&ctx->n_A);
	}
}


void wbcrypto_rsacoop_server_context_init(wbcrypto_rsacoop_server_context* ctx) {
	mbedtls_rsa_init(&ctx->client_pk, MBEDTLS_RSA_PKCS_V15, 0);
	mbedtls_rsa_init(&ctx->keypair, MBEDTLS_RSA_PKCS_V15, 0);
}

void wbcrypto_rsacoop_server_context_free(wbcrypto_rsacoop_server_context* ctx) {
	if(ctx!=NULL) {
		mbedtls_rsa_free(&ctx->client_pk);
		mbedtls_rsa_free(&ctx->keypair);
	}
}


void wbcrypto_rsacoop_keygen_client_session_init(wbcrypto_rsacoop_keygen_client_session* ctx) {
	mbedtls_mpi_init(&ctx->d_SA);
	mbedtls_rsa_init(&ctx->tmp_keypair, MBEDTLS_RSA_PKCS_V15, 0);
	wbcrypto_rsacoop_client_context_init(&ctx->key);
}

void wbcrypto_rsacoop_keygen_client_session_free(wbcrypto_rsacoop_keygen_client_session* ctx) {
	if(ctx!=NULL) {
		mbedtls_mpi_free(&ctx->d_SA);
		mbedtls_rsa_free(&ctx->tmp_keypair);
		wbcrypto_rsacoop_client_context_free(&ctx->key);
	}
}


void wbcrypto_rsacoop_keygen_server_session_init(wbcrypto_rsacoop_keygen_server_session* ctx) {
	wbcrypto_rsacoop_server_context_init(&ctx->key);
}

void wbcrypto_rsacoop_keygen_server_session_free(wbcrypto_rsacoop_keygen_server_session* ctx) {
	if(ctx!=NULL) {
		wbcrypto_rsacoop_server_context_free(&ctx->key);
	}
}


int wbcrypto_rsacoop_keygen_client_start(
	wbcrypto_rsacoop_keygen_client_session* client,
	int nbits, int exponent,
	unsigned char* req, size_t max_reqlen, size_t* reqlen,
	int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
) {
	int ret = 0;
	
	//generate key
	MBEDTLS_MPI_CHK(mbedtls_rsa_gen_key(&client->tmp_keypair, f_rng, p_rng, nbits, exponent));

	//pick d_sa and compute hd_a
	do {
		MBEDTLS_MPI_CHK(mbedtls_mpi_fill_random(&client->d_SA, mbedtls_mpi_size(&client->tmp_keypair.N) - 1, f_rng, p_rng));
		MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&client->key.hd_A, &client->tmp_keypair.D, &client->d_SA));
	} while (mbedtls_mpi_cmp_int(&client->key.hd_A, 0) < 1);

	MBEDTLS_MPI_CHK(mbedtls_rsa_import(
		&client->key.pk,
		&client->tmp_keypair.N,
		NULL, NULL, NULL,
		&client->tmp_keypair.E
	));
	MBEDTLS_MPI_CHK(mbedtls_rsa_complete(&client->key.pk));

	//write E and N into request
	MBEDTLS_MPI_CHK(write_mpi_pair(
		&client->tmp_keypair.E, &client->tmp_keypair.N, 
		req, max_reqlen, reqlen
	));

cleanup:
	return ret;
}

int wbcrypto_rsacoop_keygen_server_respond(
	wbcrypto_rsacoop_keygen_server_session* server,
	int nbits, int exponent,
	unsigned char* req, size_t req_len,
	unsigned char* resp, size_t max_resplen, size_t* resplen,
	int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
) {
	int ret = 0;
	mbedtls_mpi clientE, clientN;
	mbedtls_mpi_init(&clientE);
	mbedtls_mpi_init(&clientN);

	//generate keypair
	MBEDTLS_MPI_CHK(mbedtls_rsa_gen_key(
		&server->key.keypair, f_rng, p_rng, nbits, exponent 
	));

	//read clientPK from request
	MBEDTLS_MPI_CHK(read_mpi_pair(&clientE, &clientN, req, req_len));
	MBEDTLS_MPI_CHK(mbedtls_rsa_import(
		&server->key.client_pk,
		&clientN, NULL, NULL, NULL, &clientE
	));

	//write serverPK in response
	MBEDTLS_MPI_CHK(write_mpi_pair(
		&server->key.keypair.E, &server->key.keypair.N,
		resp, max_resplen, resplen
	));

cleanup:
	mbedtls_mpi_free(&clientE);
	mbedtls_mpi_free(&clientN);
	return ret;
}

int wbcrypto_rsacoop_keygen_client_complete(
	wbcrypto_rsacoop_keygen_client_session* client,
	unsigned char* resp, size_t resp_len
) {
	int ret = 0;
	mbedtls_mpi serverE, serverN;
	mbedtls_mpi_init(&serverE);
	mbedtls_mpi_init(&serverN);

	//read serverPK from response
	MBEDTLS_MPI_CHK(read_mpi_pair(&serverE, &serverN, resp, resp_len));

	//encrypt hda
	MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(
		&client->key.hd_SA, &client->d_SA, &serverE, &serverN, NULL
	));
	MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&client->key.n_A, &client->tmp_keypair.N));

cleanup:
	mbedtls_mpi_free(&serverE);
	mbedtls_mpi_free(&serverN);
	return ret;
}

int wbcrypto_rsacoop_keygen_client_extract_key(
	wbcrypto_rsacoop_client_context* ctx,
	wbcrypto_rsacoop_keygen_client_session* keygen_ctx
) {
	int ret = 0;

	wbcrypto_rsacoop_client_context_free(ctx);
	*ctx = keygen_ctx->key;
	wbcrypto_rsacoop_client_context_init(&keygen_ctx->key);

cleanup:
	return ret;
}

int wbcrypto_rsacoop_keygen_server_extract_key(
	wbcrypto_rsacoop_server_context* ctx,
	wbcrypto_rsacoop_keygen_server_session* keygen_ctx
) {
	int ret = 0;

	wbcrypto_rsacoop_server_context_free(ctx);
	*ctx = keygen_ctx->key;
	wbcrypto_rsacoop_server_context_init(&keygen_ctx->key);

cleanup:
	return ret;
}



int wbcrypto_rsacoop_sign_client_start(
	wbcrypto_rsacoop_client_context* client,
	const mbedtls_md_info_t* md_alg,
	const unsigned char* msg, size_t msglen,
	unsigned char* dgst, size_t max_dgstlen, size_t* dgstlen,
	unsigned char* req, size_t max_reqlen, size_t* reqlen
) {
	int ret = 0;
	size_t v15_encode_len;
	unsigned char* v15_encode = NULL;
	mbedtls_mpi t;
	mbedtls_mpi q;
	mbedtls_mpi_init(&t);
	mbedtls_mpi_init(&q);

	//run digest
	if (max_dgstlen < mbedtls_md_get_size(md_alg)) {
		return WBCRYPTO_ERR_RSACOOP_OUTPUT_TOO_LARGE;
	}
	MBEDTLS_MPI_CHK(mbedtls_md(md_alg, msg, msglen, dgst));
	*dgstlen = mbedtls_md_get_size(md_alg);

	//run digest encoding
	v15_encode_len = mbedtls_mpi_size(&client->n_A);
	v15_encode = calloc(v15_encode_len, sizeof(unsigned char));
	if (v15_encode == NULL) {
		ret = WBCRYPTO_ERR_RSACOOP_ALLOC_FAILED;
		goto cleanup;
	}
	MBEDTLS_MPI_CHK(rsa_rsassa_pkcs1_v15_encode(
		mbedtls_md_get_type(md_alg), *dgstlen, dgst,
		v15_encode_len, v15_encode
	));

	//encrypt request
	MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&t, v15_encode, v15_encode_len));
	MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&q, &t, &client->hd_A, &client->n_A, NULL));
	
	//write request
	MBEDTLS_MPI_CHK(write_rsacoop_sign_request(v15_encode, v15_encode_len, &q, &client->hd_SA, req, max_reqlen, reqlen));

cleanup:
	mbedtls_mpi_free(&q);
	mbedtls_mpi_free(&t);
	free(v15_encode);
	return ret;
}

int wbcrypto_rsacoop_sign_server_respond(
	wbcrypto_rsacoop_server_context* server,
	unsigned char* dgst, size_t dgstlen,
	unsigned char* req, size_t reqlen,
	unsigned char* resp, size_t max_resplen, size_t* resplen
) {
	int ret = 0;
	mbedtls_mpi d_SA, hd_SA, q, h, tmp;
	mbedtls_md_type_t type;
	size_t v15_encode_len;
	unsigned char* v15_encode = NULL;

	mbedtls_mpi_init(&d_SA);
	mbedtls_mpi_init(&hd_SA);
	mbedtls_mpi_init(&q);
	mbedtls_mpi_init(&h);
	mbedtls_mpi_init(&tmp);

	//read request
	MBEDTLS_MPI_CHK(read_rsacoop_sign_request(&v15_encode, &v15_encode_len, &q, &hd_SA, req, reqlen));
	MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&h, v15_encode, v15_encode_len));

	// decrypt hda
	// d_sa = (hd_sa)^d_s mod n_s
	MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&d_SA, &hd_SA, &server->keypair.D, &server->keypair.N, NULL));

	//q = q_ * h^d_sa mod n_a
	// q = (q_ mod n_a ) * (h^d_sa mod n_a) mod n_a
	//q = (q_ mod n_a )
	MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&q, &q, &server->client_pk.N));
	//tmp = (h^d_sa mod n_a)
	MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&tmp, &h, &d_SA, &server->client_pk.N, NULL));
	//q = q* tmp
	MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&q, &q, &tmp));
	//q =q mod n_a
	MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&q, &q, &server->client_pk.N));

	//tmp = q ^e_A mod n_a
	MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&tmp, &q, &server->client_pk.E, &server->client_pk.N, NULL));

	if (mbedtls_mpi_cmp_mpi(&h, &tmp) != 0) {
		ret = WBCRYPTO_ERR_RSACOOP_BAD_INPUT_DATA;
		goto cleanup;
	}

	MBEDTLS_MPI_CHK(write_rsacoop_sign_response(&q, resp, max_resplen, resplen));

cleanup:
	mbedtls_mpi_free(&hd_SA);
	mbedtls_mpi_free(&d_SA);
	mbedtls_mpi_free(&q);
	mbedtls_mpi_free(&h);
	mbedtls_mpi_free(&tmp);
	//v15encode is a ptr to somewhere in buf and not owned by us! not freed here
	return ret;
}

int wbcrypto_rsacoop_sign_client_complete(
	wbcrypto_rsacoop_client_context* client,
	unsigned char* resp, size_t resp_len,
	unsigned char* sig, size_t max_siglen, size_t* siglen
) {
	//the response is the signature, we are going through the ritual for validity test
	int ret = 0;
	mbedtls_mpi sigma;
	mbedtls_mpi_init(&sigma);
	MBEDTLS_MPI_CHK(read_rsacoop_sign_response(&sigma, resp, resp_len));
	MBEDTLS_MPI_CHK(write_rsacoop_signature(&sigma, sig, max_siglen, siglen));
cleanup:
	mbedtls_mpi_free(&sigma);
	return ret;
}

int wbcrypto_rsacoop_verify(
	mbedtls_rsa_context* client,
	const mbedtls_md_info_t* md_alg,
	const unsigned char* msg, size_t msglen,
	const unsigned char* sig, size_t siglen
) {
	int ret = 0;
	mbedtls_mpi T;
	unsigned char* out = NULL;
	size_t v15_encode_len = 0;
	unsigned char* v15_encode = NULL;
	size_t dgstlen = 0;
	unsigned char* dgst = NULL;

	mbedtls_mpi_init(&T);

	//run digest
	dgstlen = mbedtls_md_get_size(md_alg);
	dgst = calloc(dgstlen, sizeof(unsigned char));
	if (dgst == NULL) {
		ret = WBCRYPTO_ERR_RSACOOP_ALLOC_FAILED;
		goto cleanup;
	}
	MBEDTLS_MPI_CHK(mbedtls_md(md_alg, msg, msglen, dgst));

	//run digest encoding
	v15_encode_len = mbedtls_mpi_size(&client->N);
	v15_encode = calloc(v15_encode_len, sizeof(unsigned char));
	if (v15_encode == NULL) {
		ret = WBCRYPTO_ERR_RSACOOP_ALLOC_FAILED;
		goto cleanup;
	}
	MBEDTLS_MPI_CHK(rsa_rsassa_pkcs1_v15_encode(
		mbedtls_md_get_type(md_alg), 
		dgstlen, dgst,
		v15_encode_len, v15_encode
	));

	out = calloc(v15_encode_len, sizeof(unsigned char));
	if (out == NULL) {
		ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
		goto cleanup;
	}

#if defined(MBEDTLS_THREADING_C)
	if ((ret = mbedtls_mutex_lock(&ctx->mutex)) != 0)
		return (ret);
#endif

	//read T
	MBEDTLS_MPI_CHK(read_rsacoop_signature(&T, sig, siglen));
	if (mbedtls_mpi_cmp_mpi(&T, &client->N) >= 0) {
		ret = WBCRYPTO_ERR_RSACOOP_BAD_INPUT_DATA;
		goto cleanup;
	}

	//calculate dgst
	MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&T, &T, &client->E, &client->N, &client->RN));
	MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&T, out, v15_encode_len));

	//compare
	if ((ret = mbedtls_safer_memcmp(out, v15_encode, v15_encode_len)) != 0) {
		ret = WBCRYPTO_ERR_RSACOOP_VERIFY_FAILED;
		goto cleanup;
	}

cleanup:
#if defined(MBEDTLS_THREADING_C)
	if (mbedtls_mutex_unlock(&ctx->mutex) != 0)
		return (MBEDTLS_ERR_THREADING_MUTEX_ERROR);
#endif
	mbedtls_mpi_free(&T);
	free(dgst);
	free(out);
	free(v15_encode);
	return ret;
}



static int write_mpi_pair(
	const mbedtls_mpi* r, const mbedtls_mpi* s,
	unsigned char* out, size_t max_olen, size_t* olen
) {
	int ret = 0;
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
		return WBCRYPTO_ERR_RSACOOP_OUTPUT_TOO_LARGE;
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

static int read_mpi_pair(
	mbedtls_mpi* r, mbedtls_mpi* s,
	const unsigned char* data, size_t data_len
) {
	int ret = 0;
	unsigned char* now = (unsigned char*)data;
	const unsigned char* end = data + data_len;
	size_t body_length = 0;
	MBEDTLS_MPI_CHK(mbedtls_asn1_get_tag(&now, end, &body_length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
	MBEDTLS_MPI_CHK(mbedtls_asn1_get_mpi(&now, end, r));
	MBEDTLS_MPI_CHK(mbedtls_asn1_get_mpi(&now, end, s));
cleanup:
	return ret;
}

static int write_rsacoop_sign_request(
	const unsigned char* pkcs15_hash, size_t pkcs15_hash_length,
	const mbedtls_mpi* r, const mbedtls_mpi* s, 
	unsigned char* out, size_t max_olen, size_t* olen
) {
	int ret = 0;

	size_t sequence_body_size =
		wbcrypto_asn1_octet_string_buflength(pkcs15_hash_length)
		+ wbcrypto_asn1_mpi_buflength(r)
		+ wbcrypto_asn1_mpi_buflength(s)
		;

	size_t expected_size =
		WBCRYPTO_ASN1_TAG_BUFLENGTH
		+ wbcrypto_asn1_len_buflength(sequence_body_size)
		+ sequence_body_size
		;

	if (expected_size > max_olen) {
		return WBCRYPTO_ERR_RSACOOP_OUTPUT_TOO_LARGE;
	}

	*olen = expected_size;
	unsigned char* p = out + expected_size;
	WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_mpi(&p, out, s));
	WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_mpi(&p, out, r));
	WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_octet_string(&p, out, pkcs15_hash, pkcs15_hash_length));
	WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_len(&p, out, sequence_body_size));
	WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_tag(&p, out, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
	ret = 0;//asn1 writer have pos return value on success
cleanup:
	return ret;
}

static int read_rsacoop_sign_request(
	unsigned char** pkcs15_hash, size_t* pkcs15_hash_length, mbedtls_mpi* r, mbedtls_mpi* s,
	const unsigned char* data, size_t data_len
) {
	int ret = 0;
	unsigned char* now = (unsigned char*)data;
	const unsigned char* end = data + data_len;
	size_t body_length = 0;

	MBEDTLS_MPI_CHK(mbedtls_asn1_get_tag(&now, end, &body_length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
	MBEDTLS_MPI_CHK(mbedtls_asn1_get_tag(&now, end, pkcs15_hash_length, MBEDTLS_ASN1_OCTET_STRING));
	*pkcs15_hash = now;
	now += *pkcs15_hash_length;
	MBEDTLS_MPI_CHK(mbedtls_asn1_get_mpi(&now, end, r));
	MBEDTLS_MPI_CHK(mbedtls_asn1_get_mpi(&now, end, s));
cleanup:
	return ret;
}

static int write_rsacoop_sign_response(const mbedtls_mpi* sigma, unsigned char* out, size_t max_olen, size_t* olen) {
	int ret = 0;

	size_t sequence_body_size =
		wbcrypto_asn1_mpi_buflength(sigma)
		;

	size_t expected_size =
		WBCRYPTO_ASN1_TAG_BUFLENGTH
		+ wbcrypto_asn1_len_buflength(sequence_body_size)
		+ sequence_body_size
		;

	if (expected_size > max_olen) {
		return WBCRYPTO_ERR_RSACOOP_OUTPUT_TOO_LARGE;
	}

	*olen = expected_size;
	unsigned char* p = out + expected_size;
	WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_mpi(&p, out, sigma));
	WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_len(&p, out, sequence_body_size));
	WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_tag(&p, out, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
	ret = 0;//asn1 writer have pos return value on success
cleanup:
	return ret;
}

static int read_rsacoop_sign_response(mbedtls_mpi* sigma, const unsigned char* data, size_t data_len) {
	int ret = 0;
	unsigned char* now = (unsigned char*)data;
	const unsigned char* end = data + data_len;
	size_t body_length = 0;

	MBEDTLS_MPI_CHK(mbedtls_asn1_get_tag(&now, end, &body_length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
	MBEDTLS_MPI_CHK(mbedtls_asn1_get_mpi(&now, end, sigma));
cleanup:
	return ret;
}

static int write_rsacoop_signature(const mbedtls_mpi* sigma, unsigned char* out, size_t max_olen, size_t* olen) {
	return write_rsacoop_sign_response(sigma, out, max_olen, olen);
}

static int read_rsacoop_signature(mbedtls_mpi* sigma, const unsigned char* data, size_t data_len) {
	return read_rsacoop_sign_response(sigma, data, data_len);
}


//copied from mbedtls, required by rsa_rsassa_pkcs1_v15_encode
static int mbedtls_safer_memcmp(const void* a, const void* b, size_t n) {
	size_t i;
	const unsigned char* A = (const unsigned char*)a;
	const unsigned char* B = (const unsigned char*)b;
	unsigned char diff = 0;

	for (i = 0; i < n; i++)
		diff |= A[i] ^ B[i];

	return (diff);
}

static int rsa_rsassa_pkcs1_v15_encode(mbedtls_md_type_t md_alg,
	unsigned int hashlen,
	const unsigned char* hash,
	size_t dst_len,
	unsigned char* dst
) {
	size_t oid_size = 0;
	size_t nb_pad = dst_len;
	unsigned char* p = dst;
	const char* oid = NULL;

	/* Are we signing hashed or raw data? */
	if (md_alg != MBEDTLS_MD_NONE)
	{
		const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(md_alg);
		if (md_info == NULL)
			return (MBEDTLS_ERR_RSA_BAD_INPUT_DATA);

		if (mbedtls_oid_get_oid_by_md(md_alg, &oid, &oid_size) != 0)
			return (MBEDTLS_ERR_RSA_BAD_INPUT_DATA);

		hashlen = mbedtls_md_get_size(md_info);

		/* Double-check that 8 + hashlen + oid_size can be used as a
		 * 1-byte ASN.1 length encoding and that there's no overflow. */
		if (8 + hashlen + oid_size >= 0x80 ||
			10 + hashlen < hashlen ||
			10 + hashlen + oid_size < 10 + hashlen)
			return (MBEDTLS_ERR_RSA_BAD_INPUT_DATA);

		/*
		 * Static bounds check:
		 * - Need 10 bytes for five tag-length pairs.
		 *   (Insist on 1-byte length encodings to protect against variants of
		 *    Bleichenbacher's forgery attack against lax PKCS#1v1.5 verification)
		 * - Need hashlen bytes for hash
		 * - Need oid_size bytes for hash alg OID.
		 */
		if (nb_pad < 10 + hashlen + oid_size)
			return (MBEDTLS_ERR_RSA_BAD_INPUT_DATA);
		nb_pad -= 10 + hashlen + oid_size;
	}
	else
	{
		if (nb_pad < hashlen)
			return (MBEDTLS_ERR_RSA_BAD_INPUT_DATA);

		nb_pad -= hashlen;
	}

	/* Need space for signature header and padding delimiter (3 bytes),
	 * and 8 bytes for the minimal padding */
	if (nb_pad < 3 + 8)
		return (MBEDTLS_ERR_RSA_BAD_INPUT_DATA);
	nb_pad -= 3;

	/* Now nb_pad is the amount of memory to be filled
	 * with padding, and at least 8 bytes long. */

	 /* Write signature header and padding */
	*p++ = 0;
	*p++ = MBEDTLS_RSA_SIGN;
	memset(p, 0xFF, nb_pad);
	p += nb_pad;
	*p++ = 0;

	/* Are we signing raw data? */
	if (md_alg == MBEDTLS_MD_NONE)
	{
		memcpy(p, hash, hashlen);
		return (0);
	}

	/* Signing hashed data, add corresponding ASN.1 structure
	 *
	 * DigestInfo ::= SEQUENCE {
	 *   digestAlgorithm DigestAlgorithmIdentifier,
	 *   digest Digest }
	 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
	 * Digest ::= OCTET STRING
	 *
	 * Schematic:
	 * TAG-SEQ + LEN [ TAG-SEQ + LEN [ TAG-OID  + LEN [ OID  ]
	 *                                 TAG-NULL + LEN [ NULL ] ]
	 *                 TAG-OCTET + LEN [ HASH ] ]
	 */
	* p++ = MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED;
	*p++ = (unsigned char)(0x08 + oid_size + hashlen);
	*p++ = MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED;
	*p++ = (unsigned char)(0x04 + oid_size);
	*p++ = MBEDTLS_ASN1_OID;
	*p++ = (unsigned char)oid_size;
	memcpy(p, oid, oid_size);
	p += oid_size;
	*p++ = MBEDTLS_ASN1_NULL;
	*p++ = 0x00;
	*p++ = MBEDTLS_ASN1_OCTET_STRING;
	*p++ = (unsigned char)hashlen;
	memcpy(p, hash, hashlen);
	p += hashlen;

	/* Just a sanity-check, should be automatic
	 * after the initial bounds check. */
	if (p != dst + dst_len)
	{
		mbedtls_platform_zeroize(dst, dst_len);
		return (MBEDTLS_ERR_RSA_BAD_INPUT_DATA);
	}

	return (0);
}
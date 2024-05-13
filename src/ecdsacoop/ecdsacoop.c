#include "wbcrypto/ecdsacoop.h"
#include <mbedtls/rsa.h>
#include <mbedtls/ecdsa.h>
#include "wbcrypto/internal/asn1_utils.h"
#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/sha256.h"
/* x = lcm (a,b)*/
static int lcm(mbedtls_mpi *X, mbedtls_mpi *A, mbedtls_mpi *B)
{
    int ret;
    mbedtls_mpi gcd;
    mbedtls_mpi_init(&gcd);

    MBEDTLS_MPI_CHK(mbedtls_mpi_gcd(&gcd, A, B));

    MBEDTLS_MPI_CHK(mbedtls_mpi_div_mpi(X, NULL, A, &gcd));

    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(X, X, B));

cleanup:
    mbedtls_mpi_free(&gcd);
    return ret;
}

//((a^b mod c) - 1) / d
static int L(mbedtls_mpi *x, const mbedtls_mpi *a, const mbedtls_mpi *b, const mbedtls_mpi *c,
             const mbedtls_mpi *d)
{
    int ret;

    MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(x, a, b, c, NULL));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(x, x, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_div_mpi(x, NULL, x, d));

cleanup:
    return ret;
}

// gen random number from range [1,n-1]
static int gen_random_number_range(mbedtls_mpi *d, const mbedtls_mpi *N,
                                   int (*f_rng)(void *, unsigned char *, size_t),
                                   void *p_rng)
{

    size_t n_size;
    size_t need_size;
    int ret = 0;
    int count = 0;

    n_size = mbedtls_mpi_bitlen(N);
    need_size = (n_size + 7) / 8;
    do
    {
        MBEDTLS_MPI_CHK(mbedtls_mpi_fill_random(d, need_size, f_rng, p_rng));
        MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(d, 8 * need_size - n_size));

        if (++count > 30)
            return (MBEDTLS_ERR_ECP_RANDOM_FAILED);
    } while (mbedtls_mpi_cmp_int(d, 1) < 0 ||
             mbedtls_mpi_cmp_mpi(d, N) >= 0);

cleanup:
    return (ret);
}

/*client*/
int wbcrypto_ecdsa_coop_client_context_init(wbcrypto_ecdsa_coop_client_context *ctx, int grp_id)
{
    if (ctx == NULL)
    {
        return WBCRYPTO_ERR_ECDSA_COOP_INIT_FAILED;
    }
    mbedtls_ecp_group_init(&ctx->common.grp);
    mbedtls_mpi_init(&ctx->common.g);
    mbedtls_mpi_init(&ctx->common.N);
    mbedtls_mpi_init(&ctx->common.N_2);
    mbedtls_mpi_init(&ctx->k);
    mbedtls_mpi_init(&ctx->x);
    mbedtls_mpi_init(&ctx->lamda);
    mbedtls_mpi_init(&ctx->u);
    mbedtls_ecp_point_init(&ctx->R);
    return mbedtls_ecp_group_load(&ctx->common.grp, grp_id);
}

void wbcrypto_ecdsa_coop_client_context_free(wbcrypto_ecdsa_coop_client_context *ctx)
{
    if (ctx != NULL)
    {
        mbedtls_ecp_group_free(&ctx->common.grp);
        mbedtls_mpi_free(&ctx->common.g);
        mbedtls_mpi_free(&ctx->common.N);
        mbedtls_mpi_free(&ctx->common.N_2);
        mbedtls_mpi_free(&ctx->lamda);
        mbedtls_mpi_free(&ctx->k);
        mbedtls_mpi_free(&ctx->x);
        mbedtls_mpi_free(&ctx->u);
        mbedtls_ecp_point_free(&ctx->R);
    }
    ctx = NULL;
}

int wbcrypto_ecdsa_coop_client_gen_params(wbcrypto_ecdsa_coop_client_context *ctx, int (*f_rng)(void *, unsigned char *, size_t),
                                          void *p_rng)
{
    int ret;
    mbedtls_mpi p1;
    mbedtls_mpi p2;
    mbedtls_rsa_context tmp;

    mbedtls_mpi_init(&p1);
    mbedtls_mpi_init(&p2);

    mbedtls_rsa_init(&tmp, MBEDTLS_RSA_PKCS_V21, 0);
    MBEDTLS_MPI_CHK(mbedtls_rsa_gen_key(&tmp, f_rng, p_rng, PRIME_BITE_SIZE, 3));

    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&p1, &tmp.P));
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&p2, &tmp.Q));

    // N = p1 * p2
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&ctx->common.N, &p1, &p2));
    // N^2
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&ctx->common.N_2, &ctx->common.N, &ctx->common.N));
    // g = N + 1
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&ctx->common.g, &ctx->common.N, 1));
    // p1 = p1 -1
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&p1, &p1, 1));
    // p2 = p2 -1
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&p2, &p2, 1));
    // lamda = lcm
    MBEDTLS_MPI_CHK(lcm(&ctx->lamda, &p1, &p2));
    // u =  L
    MBEDTLS_MPI_CHK(L(&ctx->u, &ctx->common.g, &ctx->lamda, &ctx->common.N_2, &ctx->common.N));
    // u^(-1) mod N
    MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(&ctx->u, &ctx->u, &ctx->common.N));
    // //R = k * G
    MBEDTLS_MPI_CHK(mbedtls_ecp_gen_keypair(&ctx->common.grp, &ctx->k, &ctx->R, f_rng, p_rng));

cleanup:
    mbedtls_mpi_free(&p1);
    mbedtls_mpi_free(&p2);
    mbedtls_rsa_free(&tmp);
    return ret;
}

int wbcrypto_ecdsa_coop_client_gen_ek(wbcrypto_ecdsa_coop_client_context *ctx, mbedtls_mpi *ek,
                                      int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret;
    mbedtls_mpi p1;
    mbedtls_mpi p2;
    mbedtls_mpi r1;
    mbedtls_mpi RR;

    mbedtls_mpi_init(&p1);
    mbedtls_mpi_init(&p2);
    mbedtls_mpi_init(&r1);
    mbedtls_mpi_init(&RR);

    // random x r1
    MBEDTLS_MPI_CHK(mbedtls_ecp_gen_privkey(&ctx->common.grp, &ctx->x, f_rng, p_rng));
    MBEDTLS_MPI_CHK(gen_random_number_range(&r1, &ctx->common.N, f_rng, p_rng));

    MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&p1, &ctx->common.g, &ctx->x, &ctx->common.N_2, &RR));
    // r1 ^ N
    MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&p2, &r1, &ctx->common.N, &ctx->common.N_2, &RR));
    // ek = g^x * r1 ^ N
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(ek, &p1, &p2));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(ek, ek, &ctx->common.N_2));
cleanup:
    mbedtls_mpi_free(&p1);
    mbedtls_mpi_free(&p2);
    mbedtls_mpi_free(&RR);
    return ret;
}

int wbcrypto_ecdsa_coop_client_gen_Pk(wbcrypto_ecdsa_coop_client_context *ctx, const mbedtls_ecp_point *Ps, mbedtls_ecp_point *Pk)
{
    int ret;
    mbedtls_mpi one;
    mbedtls_mpi_init(&one);

    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&one, 1));

    MBEDTLS_MPI_CHK(mbedtls_ecp_muladd(&ctx->common.grp, Pk, &one, Ps, &ctx->x, &ctx->common.grp.G));

cleanup:
    mbedtls_mpi_free(&one);
    return ret;
}

int wbcrypto_ecdsa_coop_client_sign(wbcrypto_ecdsa_coop_client_context *ctx,
                                    const mbedtls_mpi *ex, const mbedtls_mpi *ps,
                                    const mbedtls_mpi *r, mbedtls_mpi *s)
{
    int ret;
    mbedtls_mpi otx;

    mbedtls_mpi_init(&otx);
    //L
    MBEDTLS_MPI_CHK(L(&otx, ex, &ctx->lamda, &ctx->common.N_2, &ctx->common.N));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&otx, &otx, &ctx->u));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&otx, &otx, &ctx->common.N));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&otx, &otx, &ctx->common.grp.N));

    mbedtls_mpi_inv_mod(s, &ctx->k, &ctx->common.grp.N);
    mbedtls_mpi_mul_mpi(&otx, &otx, r);
    mbedtls_mpi_add_mpi(&otx, &otx, ps);
    mbedtls_mpi_mul_mpi(s, s, &otx);
    mbedtls_mpi_mod_mpi(s, s, &ctx->common.grp.N);

cleanup:
    mbedtls_mpi_free(&otx);
    return ret;
}

int wbcrypto_ecdsa_coop_client_precompute(wbcrypto_ecdsa_coop_client_context *ctx,
                                          int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    //R = k * G
    return (mbedtls_ecp_gen_keypair(&ctx->common.grp, &ctx->k, &ctx->R, f_rng, p_rng));
}

/////////////////////////////////////////////////////////////////////////////////////////
//
//
//
/////////////////////////////////////////////////////////////////////////////////////////
/*server*/
int wbcrypto_ecdsa_coop_server_context_init(wbcrypto_ecdsa_coop_server_context *ctx, int grp_id)
{
    if (ctx == NULL)
    {
        return WBCRYPTO_ERR_ECDSA_COOP_INIT_FAILED;
    }
    mbedtls_ecp_group_init(&ctx->common.grp);
    mbedtls_mpi_init(&ctx->common.g);
    mbedtls_mpi_init(&ctx->common.N);
    mbedtls_mpi_init(&ctx->common.N_2);
    mbedtls_mpi_init(&ctx->k);
    mbedtls_mpi_init(&ctx->ex);
    mbedtls_mpi_init(&ctx->ek);
    mbedtls_mpi_init(&ctx->otx);
    mbedtls_mpi_init(&ctx->x);
    return mbedtls_ecp_group_load(&ctx->common.grp, grp_id);
}


  int wbcrypto_ecdsa_coop_keygen_client_context_init(wbcrypto_ecdsa_coop_keygen_client_context* ctx, int grp_id) {
	return wbcrypto_ecdsa_coop_client_context_init(&ctx->key, grp_id);
    }

    int wbcrypto_ecdsa_coop_keygen_server_context_init(wbcrypto_ecdsa_coop_keygen_server_context* ctx, int grp_id) {
	return wbcrypto_ecdsa_coop_server_context_init(&ctx->key, grp_id);
    }


void wbcrypto_ecdsa_coop_server_context_free(wbcrypto_ecdsa_coop_server_context *ctx)
{
    if (ctx != NULL)
    {
        mbedtls_ecp_group_free(&ctx->common.grp);
        mbedtls_mpi_free(&ctx->common.g);
        mbedtls_mpi_free(&ctx->common.N);
        mbedtls_mpi_free(&ctx->common.N_2);
        mbedtls_mpi_free(&ctx->k);
        mbedtls_mpi_free(&ctx->otx);
        mbedtls_mpi_free(&ctx->ex);
        mbedtls_mpi_free(&ctx->ek);
        mbedtls_mpi_free(&ctx->x);
    }
    ctx = NULL;
}
int wbcrypto_ecdsa_coop_server_gen_params(wbcrypto_ecdsa_coop_server_context *ctx,
                                          const wbcrypto_ecdsa_coop_common *ccom,
                                          const mbedtls_mpi *ek,
                                          int (*f_rng)(void *, unsigned char *, size_t),
                                          void *p_rng)
{
    int ret;
    mbedtls_mpi b0;
    mbedtls_mpi b1;
    mbedtls_mpi rho;
    mbedtls_mpi q4;

    mbedtls_mpi_init(&b0);
    mbedtls_mpi_init(&b1);
    mbedtls_mpi_init(&q4);
    mbedtls_mpi_init(&rho);

    // copy
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&ctx->common.g, &ccom->g));
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&ctx->common.N, &ccom->N));
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&ctx->common.N_2, &ccom->N_2));
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&ctx->ek, ek));

    // random x  k b0
    MBEDTLS_MPI_CHK(mbedtls_ecp_gen_privkey(&ctx->common.grp, &ctx->k, f_rng, p_rng));

    MBEDTLS_MPI_CHK(mbedtls_ecp_gen_privkey(&ctx->common.grp, &ctx->x, f_rng, p_rng));
    MBEDTLS_MPI_CHK(mbedtls_ecp_gen_privkey(&ctx->common.grp, &b0, f_rng, p_rng));

    // b1 = k^(-1) mod q
    MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(&b1, &ctx->k, &ctx->common.grp.N));

    //otx
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&ctx->otx, &b0, &ctx->k));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&ctx->otx, &ctx->x, &ctx->otx));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&ctx->otx, &ctx->otx, &ctx->common.grp.N));

    // random rho
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&q4, &ctx->common.grp.N, &ctx->common.grp.N));
    MBEDTLS_MPI_CHK(gen_random_number_range(&rho, &q4, f_rng, p_rng));

    //ex
    // b0+rho*q
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&rho, &rho, &ctx->common.grp.N));
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&rho, &rho, &b0));

    // g^ (b0+rho*q)
    mbedtls_mpi_free(&q4);
    mbedtls_mpi_free(&b0);
    MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&b0, &ctx->common.g, &rho, &ctx->common.N_2, &q4));

    // ek ^b1
    mbedtls_mpi_free(&rho);
    MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&rho, &ctx->ek, &b1, &ctx->common.N_2, &q4));

    // ex = ek ^b1 *  g^ rho
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&ctx->ex, &b0, &rho));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&ctx->ex, &ctx->ex, &ctx->common.N_2));

cleanup:
    mbedtls_mpi_free(&b0);
    mbedtls_mpi_free(&b1);
    mbedtls_mpi_free(&q4);
    mbedtls_mpi_free(&rho);
    return ret;
}


/**
	write point in such ASN.1 DER format:
	SEQENCE(
		XCoordinate INTEGER,
		YCoordinate INTEGER
	)
*/
static int write_ecp_point(
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
		ret = WBCRYPTO_ERR_ECDSA_COOP_OUTPUT_TOO_LARGE;
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

/**
	read point in the format above
*/
static int read_ecp_point(
	mbedtls_ecp_point* p,
	const unsigned char* data, size_t data_len
) {
	int ret = 0;
	unsigned char* now = (unsigned char*)data;
	const unsigned char* end = data + data_len;
	size_t body_length = 0;
	MBEDTLS_MPI_CHK(mbedtls_asn1_get_tag(&now, end, &body_length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
	MBEDTLS_MPI_CHK(mbedtls_asn1_get_mpi(&now, end, &p->X));
	MBEDTLS_MPI_CHK(mbedtls_asn1_get_mpi(&now, end, &p->Y));
	MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&p->Z, 1));
cleanup:
	return ret;
}

/**
	write ek, g, N, N^2 in such ASN.1 DER format:
	SEQENCE(
		ek INTEGER,
		g INTEGER,
        N INTEGER,
        N^2 INTEGER
	)
*/
static int write_ek_g_Ns(
    mbedtls_mpi *ek,
    mbedtls_mpi *g,
    mbedtls_mpi *N,
    mbedtls_mpi *N_2,
    unsigned char* out, size_t max_olen, size_t* olen
){
    int ret = 0;
    size_t ek_full_size = wbcrypto_asn1_mpi_buflength(ek);
    size_t g_full_size = wbcrypto_asn1_mpi_buflength(g);
    size_t N_full_size = wbcrypto_asn1_mpi_buflength(N);
    size_t N_2_full_size = wbcrypto_asn1_mpi_buflength(N_2);
    size_t full_data_size = ek_full_size + g_full_size + N_full_size + N_2_full_size;
    size_t full_size = 
        WBCRYPTO_ASN1_TAG_BUFLENGTH 
        + wbcrypto_asn1_len_buflength(full_data_size)
        + full_data_size;


    if (max_olen < full_size) {
		ret = WBCRYPTO_ERR_ECDSA_COOP_OUTPUT_TOO_LARGE;
		goto cleanup;
	}

    unsigned char* p = out + full_size;
    WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_mpi(&p, out, ek));
    WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_mpi(&p, out, g));
    WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_mpi(&p, out, N));
    WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_mpi(&p, out, N_2));
    WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_len(&p, out, full_data_size));
	WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_tag(&p, out, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    *olen = full_size;
    ret = 0; // their retval is non-zero on success
cleanup:
	return ret;

}

/**
	read mpis in the format above
*/
static int read_ek_g_Ns(
	mbedtls_mpi *ek,
    mbedtls_mpi *g,
    mbedtls_mpi *N,
    mbedtls_mpi *N_2,
	const unsigned char* data, size_t data_len
) {
	int ret = 0;
	unsigned char* now = (unsigned char*)data;
	const unsigned char* end = data + data_len;
	size_t body_length = 0;
	MBEDTLS_MPI_CHK(mbedtls_asn1_get_tag(&now, end, &body_length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
	MBEDTLS_MPI_CHK(mbedtls_asn1_get_mpi(&now, end, ek));
	MBEDTLS_MPI_CHK(mbedtls_asn1_get_mpi(&now, end, g));
	MBEDTLS_MPI_CHK(mbedtls_asn1_get_mpi(&now, end, N));
    MBEDTLS_MPI_CHK(mbedtls_asn1_get_mpi(&now, end, N_2));
cleanup:
	return ret;
}



/**
	write ek, g, N, N^2 in such ASN.1 DER format:
	SEQENCE(
		r INTEGER,
		ps INTEGER,
        ex INTEGER
	)
*/
static int write_r_ps_ex(
    mbedtls_mpi *r,
    mbedtls_mpi *ps,
    mbedtls_mpi *ex,
    unsigned char* out, size_t max_olen, size_t* olen
){
    int ret = 0;
    size_t r_full_size = wbcrypto_asn1_mpi_buflength(r);
    size_t ps_full_size = wbcrypto_asn1_mpi_buflength(ps);
    size_t ex_full_size = wbcrypto_asn1_mpi_buflength(ex);

    size_t full_data_size = r_full_size + ps_full_size + ex_full_size;
    size_t full_size = 
        WBCRYPTO_ASN1_TAG_BUFLENGTH 
        + wbcrypto_asn1_len_buflength(full_data_size)
        + full_data_size;


    if (max_olen < full_size) {
		ret = WBCRYPTO_ERR_ECDSA_COOP_OUTPUT_TOO_LARGE;
		goto cleanup;
	}

    unsigned char* p = out + full_size;
    WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_mpi(&p, out, r));
    WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_mpi(&p, out, ps));
    WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_mpi(&p, out, ex));
    WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_len(&p, out, full_data_size));
	WBCRYPTO_THROW_ON_NEG(mbedtls_asn1_write_tag(&p, out, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    *olen = full_size;
    ret = 0; // their retval is non-zero on success
cleanup:
	return ret;

}

/**
	read mpis in the format above
*/
static int read_r_ps_ex(
	mbedtls_mpi *r,
    mbedtls_mpi *ps,
    mbedtls_mpi *ex,
	const unsigned char* data, size_t data_len
) {
	int ret = 0;
	unsigned char* now = (unsigned char*)data;
	const unsigned char* end = data + data_len;
	size_t body_length = 0;
	MBEDTLS_MPI_CHK(mbedtls_asn1_get_tag(&now, end, &body_length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
	MBEDTLS_MPI_CHK(mbedtls_asn1_get_mpi(&now, end, r));
	MBEDTLS_MPI_CHK(mbedtls_asn1_get_mpi(&now, end, ps));
	MBEDTLS_MPI_CHK(mbedtls_asn1_get_mpi(&now, end, ex));
cleanup:
	return ret;
}


//write mpi r and s in ASN.1 struct format (same as SM2 Signature)
static int ecdsa_write_r_s(
	const mbedtls_mpi* r, const mbedtls_mpi* s,
	unsigned char* out, size_t max_olen, size_t* olen
){
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
		return WBCRYPTO_ERR_ECDSA_COOP_OUTPUT_TOO_LARGE;
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

//read mpi r and s in ASN.1 struct format (same as SM2 Signature)
static int ecdsa_read_r_s(
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



int wbcrypto_ecdsa_coop_server_gen_raw_params(wbcrypto_ecdsa_coop_server_context *ctx,
                                          const mbedtls_mpi *g,
                                          const mbedtls_mpi *N,
                                          const mbedtls_mpi *N_2,
                                          const mbedtls_mpi *ek,
                                          int (*f_rng)(void *, unsigned char *, size_t),
                                          void *p_rng)
{
    int ret;
    mbedtls_mpi b0;
    mbedtls_mpi b1;
    mbedtls_mpi rho;
    mbedtls_mpi q4;

    mbedtls_mpi_init(&b0);
    mbedtls_mpi_init(&b1);
    mbedtls_mpi_init(&q4);
    mbedtls_mpi_init(&rho);

    // copy
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&ctx->common.g, g));
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&ctx->common.N, N));
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&ctx->common.N_2,N_2));
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&ctx->ek, ek));

    // random x  k b0
    MBEDTLS_MPI_CHK(mbedtls_ecp_gen_privkey(&ctx->common.grp, &ctx->k, f_rng, p_rng));

    MBEDTLS_MPI_CHK(mbedtls_ecp_gen_privkey(&ctx->common.grp, &ctx->x, f_rng, p_rng));
    MBEDTLS_MPI_CHK(mbedtls_ecp_gen_privkey(&ctx->common.grp, &b0, f_rng, p_rng));

    // b1 = k^(-1) mod q
    MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(&b1, &ctx->k, &ctx->common.grp.N));

    //otx
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&ctx->otx, &b0, &ctx->k));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&ctx->otx, &ctx->x, &ctx->otx));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&ctx->otx, &ctx->otx, &ctx->common.grp.N));

    // random rho
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&q4, &ctx->common.grp.N, &ctx->common.grp.N));
    MBEDTLS_MPI_CHK(gen_random_number_range(&rho, &q4, f_rng, p_rng));

    //ex
    // b0+rho*q
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&rho, &rho, &ctx->common.grp.N));
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&rho, &rho, &b0));

    // g^ (b0+rho*q)
    mbedtls_mpi_free(&q4);
    mbedtls_mpi_free(&b0);
    MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&b0, &ctx->common.g, &rho, &ctx->common.N_2, &q4));

    // ek ^b1
    mbedtls_mpi_free(&rho);
    MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&rho, &ctx->ek, &b1, &ctx->common.N_2, &q4));

    // ex = ek ^b1 *  g^ rho
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&ctx->ex, &b0, &rho));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&ctx->ex, &ctx->ex, &ctx->common.N_2));

cleanup:
    mbedtls_mpi_free(&b0);
    mbedtls_mpi_free(&b1);
    mbedtls_mpi_free(&q4);
    mbedtls_mpi_free(&rho);
    return ret;
}

int wbcrypto_ecdsa_coop_server_gen_Ps(wbcrypto_ecdsa_coop_server_context *ctx, mbedtls_ecp_point *Ps,
                                      int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    // P = x * G
    return mbedtls_ecp_mul(&ctx->common.grp, Ps, &ctx->x, &ctx->common.grp.G, f_rng, p_rng);
}

int wbcrypto_ecdsa_coop_server_sign(wbcrypto_ecdsa_coop_server_context *ctx,
                                    const mbedtls_ecp_point *Ra, const mbedtls_mpi *h,
                                    mbedtls_mpi *ps, mbedtls_mpi *r,
                                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret;
    mbedtls_ecp_point tmp;
    mbedtls_mpi b;

    mbedtls_ecp_point_init(&tmp);
    mbedtls_mpi_init(&b);

    // x,y = ks * Ra
    MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&ctx->common.grp, &tmp, &ctx->k, Ra, f_rng, p_rng));
    // r = x mod q
    mbedtls_mpi_mod_mpi(r, &tmp.X, &ctx->common.grp.N);

    mbedtls_mpi_inv_mod(ps, &ctx->k, &ctx->common.grp.N);
    mbedtls_mpi_mul_mpi(&b, r, &ctx->otx);
    mbedtls_mpi_add_mpi(&b, &b, h);
    mbedtls_mpi_mul_mpi(&b, &b, ps);
    mbedtls_mpi_mod_mpi(ps, &b, &ctx->common.grp.N);

cleanup:
    mbedtls_ecp_point_free(&tmp);
    mbedtls_mpi_free(&b);
    return ret;
}

int wbcrypto_ecdsa_coop_keygen_client_send_key(
	wbcrypto_ecdsa_coop_keygen_client_context* ctx,
	unsigned char* client_params, size_t max_client_params_len, size_t* client_params_len,
	int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
) {
	int ret = 0;
    mbedtls_mpi ek;
    mbedtls_mpi_init(&ek);
    size_t len;

    MBEDTLS_MPI_CHK(wbcrypto_ecdsa_coop_client_gen_params(ctx, f_rng, p_rng));

    MBEDTLS_MPI_CHK(wbcrypto_ecdsa_coop_client_gen_ek(ctx, &ek, f_rng, p_rng));

    MBEDTLS_MPI_CHK(write_ek_g_Ns(&ek, &ctx->key.common.g, 
        &ctx->key.common.N, 
        &ctx->key.common.N_2, client_params, max_client_params_len, client_params_len));


cleanup:
	return ret;
}
    
int wbcrypto_ecdsa_coop_keygen_server_exchange_key(
	wbcrypto_ecdsa_coop_keygen_server_context* ctx,
	const unsigned char* client_param, size_t client_param_len,
	unsigned char* server_Ps, size_t max_server_Ps_len, size_t* server_Ps_len,
	int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
){
	int ret = 0;

    mbedtls_mpi ek;
    mbedtls_mpi g;
    mbedtls_mpi N;
    mbedtls_mpi N_2;
    mbedtls_ecp_point Ps;
    mbedtls_ecp_point Pk;


    mbedtls_mpi_init(&ek);
    mbedtls_mpi_init(&g);
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&N_2);
    mbedtls_ecp_point_init(&Ps);
    mbedtls_ecp_point_init(&Pk);
    
    MBEDTLS_MPI_CHK(read_ek_g_Ns(&ek, &g, &N, &N_2, client_param, client_param_len));

    MBEDTLS_MPI_CHK(wbcrypto_ecdsa_coop_server_gen_raw_params(ctx, &g, &N, &N_2, &ek, f_rng, p_rng));

    MBEDTLS_MPI_CHK(wbcrypto_ecdsa_coop_server_gen_Ps(ctx, &Ps, f_rng, p_rng));
    
    MBEDTLS_MPI_CHK(write_ecp_point(&Ps, server_Ps, max_server_Ps_len, server_Ps_len));


cleanup:
	return ret;
}



int wbcrypto_ecdsa_coop_keygen_client_receive_key(
	wbcrypto_ecdsa_coop_keygen_client_context* ctx,
	const unsigned char* server_Ps, size_t server_Ps_len
) {
	int ret = 0;
	mbedtls_ecp_point Pk;
    mbedtls_ecp_point Ps;

	mbedtls_ecp_point_init(&Pk);
    mbedtls_ecp_point_init(&Ps);

	MBEDTLS_MPI_CHK(read_ecp_point(&Ps, server_Ps, server_Ps_len));


    wbcrypto_ecdsa_coop_client_gen_Pk(ctx, &Ps, &Pk);
    
cleanup:

	return ret;
}


int wbcrypto_ecdsa_coop_sign_client_start(
    wbcrypto_ecdsa_coop_client_context *ctx,
    const unsigned char *msg, size_t msglen,
    unsigned char *dgst, size_t max_dgstlen,
    size_t* dgstlen, unsigned char* req, size_t max_reqlen, size_t* reqlen,
    int (*f_rng)(void*, unsigned char*, size_t), void* p_rng)
{

    int ret;

    /* compute digest */

    MBEDTLS_MPI_CHK(mbedtls_sha256_ret(msg, msglen, dgst, 0));
    *dgst = 32;

    MBEDTLS_MPI_CHK(write_ecp_point(&ctx->R, req,max_reqlen, reqlen));

    
    cleanup:
    	return ret;
    



}


int wbcrypto_ecdsa_coop_sign_server_respond(
	wbcrypto_ecdsa_coop_server_context* ctx,
	const unsigned char* dgst, size_t dgst_len,
	const unsigned char* req, size_t req_len,
	unsigned char* resp, size_t max_resplen, size_t* resplen,
	int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
)  
{

    int ret;

    mbedtls_ecp_point Ra;
    mbedtls_mpi h;
    mbedtls_mpi ps;
    mbedtls_mpi r;
    mbedtls_mpi s;

    mbedtls_mpi_init(&h);
    mbedtls_ecp_point_init(&Ra);
    mbedtls_mpi_init(&ps);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&h, dgst, dgst_len));
    MBEDTLS_MPI_CHK(read_ecp_point(&Ra, req,req_len));
    MBEDTLS_MPI_CHK(wbcrypto_ecdsa_coop_server_sign(ctx, &Ra, &h, &ps, &r, f_rng, p_rng));
    MBEDTLS_MPI_CHK(write_r_ps_ex(&r, &ps, &ctx->ex, resp, max_resplen, resplen));

    


    cleanup:
        return ret;

}


int wbcrypto_ecdsa_coop_sign_client_complete(
	wbcrypto_ecdsa_coop_client_context* ctx,
	unsigned char* resp, size_t resplen,
	unsigned char* sig, size_t max_siglen, size_t* siglen,
	int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
)
{

    int ret;
    mbedtls_mpi r, s;
    mbedtls_mpi ps;
    mbedtls_mpi ex;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&ps);
    mbedtls_mpi_init(&ex);
    mbedtls_mpi_init(&s);
    MBEDTLS_MPI_CHK(read_r_ps_ex(&r, &ps, &ex, resp, resplen ));

    MBEDTLS_MPI_CHK(wbcrypto_ecdsa_coop_client_sign(ctx, &ex, &ps, &r, &ps));

    MBEDTLS_MPI_CHK(ecdsa_write_r_s(&r, &s, sig, max_siglen, siglen));


    cleanup:
    return ret;


}






/*server precompute*/
int wbcrypto_ecdsa_coop_server_precompute(wbcrypto_ecdsa_coop_server_context *ctx,
                                          int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret;
    mbedtls_mpi b0;
    mbedtls_mpi b1;
    mbedtls_mpi rho;
    mbedtls_mpi q4;

    mbedtls_mpi_init(&b0);
    mbedtls_mpi_init(&b1);
    mbedtls_mpi_init(&q4);
    mbedtls_mpi_init(&rho);

    // random  k b0
    MBEDTLS_MPI_CHK(mbedtls_ecp_gen_privkey(&ctx->common.grp, &ctx->k, f_rng, p_rng));
    MBEDTLS_MPI_CHK(mbedtls_ecp_gen_privkey(&ctx->common.grp, &b0, f_rng, p_rng));

    // b1 = k^(-1) mod q
    MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(&b1, &ctx->k, &ctx->common.grp.N));

    //otx
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&ctx->otx, &b0, &ctx->k));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&ctx->otx, &ctx->x, &ctx->otx));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&ctx->otx, &ctx->otx, &ctx->common.grp.N));

    // random rho
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&q4, &ctx->common.grp.N, &ctx->common.grp.N));
    MBEDTLS_MPI_CHK(gen_random_number_range(&rho, &q4, f_rng, p_rng));

    //ex
    // b0+rho*q
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&rho, &rho, &ctx->common.grp.N));
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&rho, &rho, &b0));

    // g^ (b0+rho*q)
    mbedtls_mpi_free(&q4);
    mbedtls_mpi_free(&b0);
    MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&b0, &ctx->common.g, &rho, &ctx->common.N_2, &q4));

    // ek ^b1
    mbedtls_mpi_free(&rho);
    MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&rho, &ctx->ek, &b1, &ctx->common.N_2, &q4));

    // ex = ek ^b1 *  g^ rho
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&ctx->ex, &b0, &rho));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&ctx->ex, &ctx->ex, &ctx->common.N_2));

cleanup:
    mbedtls_mpi_free(&b0);
    mbedtls_mpi_free(&b1);
    mbedtls_mpi_free(&q4);
    mbedtls_mpi_free(&rho);
    return ret;
}

int wbcrypto_ecdsa_coop_verify_sign(mbedtls_ecp_group *grp,
                                    const unsigned char *hash_msg, size_t hash_len,
                                    const mbedtls_ecp_point *Pk,
                                    const mbedtls_mpi *r,
                                    const mbedtls_mpi *s)
{
    return mbedtls_ecdsa_verify(grp, hash_msg, hash_len, Pk, r, s);
}



/////////////////////////////////////////////////////////////////////////////////////////
//
//
//
/////////////////////////////////////////////////////////////////////////////////////////
/*test*/
int test_ecdsa_coop_scheme(mbedtls_mpi *rr, mbedtls_mpi *ss,
                           const unsigned char *hash_msg, size_t hash_len,
                           int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret;

    wbcrypto_ecdsa_coop_client_context client;
    wbcrypto_ecdsa_coop_server_context server;
    mbedtls_mpi ek;
    mbedtls_mpi r;
    mbedtls_mpi s;
    mbedtls_mpi ps;
    mbedtls_mpi h;
    mbedtls_ecp_point Ps;
    mbedtls_ecp_point Pk;

    mbedtls_ecp_point_init(&Ps);
    mbedtls_ecp_point_init(&Pk);
    mbedtls_mpi_init(&ek);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    mbedtls_mpi_init(&ps);
    mbedtls_mpi_init(&h);
    MBEDTLS_MPI_CHK(wbcrypto_ecdsa_coop_client_context_init(&client, MBEDTLS_ECP_DP_SECP256R1));
    MBEDTLS_MPI_CHK(wbcrypto_ecdsa_coop_server_context_init(&server, MBEDTLS_ECP_DP_SECP256R1));

    /////////////////////////////////////////set up //////////////////////////////////////

    // client set up
    MBEDTLS_MPI_CHK(wbcrypto_ecdsa_coop_client_gen_params(&client, f_rng, p_rng));

    // generate ek
    MBEDTLS_MPI_CHK(wbcrypto_ecdsa_coop_client_gen_ek(&client, &ek, f_rng, p_rng));
    // send ek , g, N ,N^2 to server  ......>

    ////////////////////

    // server receive sth.. ek , g, N ,N^2
    // and server set up
    MBEDTLS_MPI_CHK(wbcrypto_ecdsa_coop_server_gen_params(&server, &client.common, &ek, f_rng, p_rng));
    // generate ps
    MBEDTLS_MPI_CHK(wbcrypto_ecdsa_coop_server_gen_Ps(&server, &Ps, f_rng, p_rng));

    ////////////////////

    // client generate Pk
    MBEDTLS_MPI_CHK(wbcrypto_ecdsa_coop_client_gen_Pk(&client, &Ps, &Pk));
    // send pk to server

    /////////////////////////////done///////////////////////////////////////////////////////////////////////

    ////////////////////start signature/////////////////////////////
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&h, hash_msg, hash_len));
    MBEDTLS_MPI_CHK(wbcrypto_ecdsa_coop_server_sign(&server, &client.R, &h, &ps, &r, f_rng, p_rng));
    MBEDTLS_MPI_CHK(wbcrypto_ecdsa_coop_client_sign(&client, &server.ex, &ps, &r, &s));
    ////////////////////done signature/////////////////////////////

    MBEDTLS_MPI_CHK(wbcrypto_ecdsa_coop_verify_sign(&client.common.grp, hash_msg, hash_len, &Pk, &r, &s));

    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(rr, &r));
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(ss, &s));
cleanup:
    mbedtls_mpi_free(&ek);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&ps);
    mbedtls_mpi_free(&h);
    mbedtls_ecp_point_free(&Ps);
    mbedtls_ecp_point_free(&Pk);
    wbcrypto_ecdsa_coop_client_context_free(&client);
    wbcrypto_ecdsa_coop_server_context_free(&server);

    return ret;
}
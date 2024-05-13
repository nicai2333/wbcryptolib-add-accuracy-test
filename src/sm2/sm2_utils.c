#include <stdlib.h>
#include <memory.h>
#include "mbedtls/asn1write.h"
#include "mbedtls/asn1.h"
#include "crypto/sm3.h"
#include "crypto/sm2.h"
#include "wbcrypto/internal/sm2/sm2_utils.h"

#define int_to_byte_4(b, i, u)         \
	b[i] = (unsigned char)(u >> 8);    \
	b[i+1] = (unsigned char)(u)

#define int_to_byte_8(b, i, u)         \
	b[i] = (unsigned char)(u >> 24);   \
	b[i+1] = (unsigned char)(u >> 16); \
	b[i+2] = (unsigned char)(u >> 8);  \
	b[i+3] = (unsigned char)(u)        \

int wbcrypto_sm2_compute_hashedMbar(
	wbcrypto_sm2_context* ctx,
	const unsigned char* id, size_t idlen,
	const unsigned char* message, size_t msglen,
	unsigned char* out
) {

	int ret;
	size_t hasg_len = SM3_DIGEST_LENGTH + msglen;
	unsigned char* hash = calloc(hasg_len, sizeof(unsigned char));

	size_t len_idlen = 2;
	size_t p_len = mbedtls_mpi_size(&(ctx->grp.P));
	size_t z_len = len_idlen + idlen + p_len * 6;
	unsigned char* z_buf = calloc(z_len, sizeof(unsigned char));

	if (hash == NULL || z_buf == NULL) {
		return WBCRYPTO_ERR_SM2_ALLOC_FAILED;
	}

	/* z += ENTLa */
	int_to_byte_4(z_buf, 0, idlen * 8);
	/* z += id*/
	memcpy(z_buf + len_idlen, id, idlen);
	/* z += a*/
	MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(
		&(ctx->grp.A), 
		z_buf + len_idlen + idlen, p_len
	));
	/* z += b*/
	MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(
		&(ctx->grp.B),
		z_buf + len_idlen + idlen + p_len, p_len
	));
	/* z += gx*/
	MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(
		&(ctx->grp.G.X),
		z_buf + len_idlen + idlen + p_len * 2, p_len
	));
	/* z +=gy*/
	MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(
		&(ctx->grp.G.Y),
		z_buf + len_idlen + idlen + p_len * 3, p_len
	));
	/* z += pk.x*/
	MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(
		&(ctx->Pb.X),
		z_buf + len_idlen + idlen + p_len * 4, p_len
	));
	/* z += pk.y*/
	MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(
		&(ctx->Pb.Y),
		z_buf + len_idlen + idlen + p_len * 5, p_len
	));
	/*sm3 z*/
	wbcrypto_sm3(z_buf, z_len, hash);

	memcpy(hash + SM3_DIGEST_LENGTH, message, msglen);

	/*h(m)*/
	wbcrypto_sm3(hash, hasg_len, out);

cleanup:
	free(hash);
	free(z_buf);
	return (ret);
}

//run SM2 KDF on buffer, write to output
int kdf(
	unsigned char* out, 
	const unsigned char* buf, size_t buf_len, 
	size_t klen
) {
	const int CT_LEN = sizeof(uint32_t);
	const size_t counts = klen / SM3_DIGEST_LENGTH;
	const size_t mod = klen % SM3_DIGEST_LENGTH;

	size_t tmp_len = buf_len + CT_LEN;
	uint32_t ct;
	//buf len  + ct len ()
	unsigned char* buf_z_ct = calloc(tmp_len, sizeof(unsigned char));
	unsigned char* temp_out = calloc(SM3_DIGEST_LENGTH, sizeof(unsigned char));

	if (buf_z_ct == NULL || temp_out == NULL) {
		free(buf_z_ct);
		free(temp_out);
		return WBCRYPTO_ERR_SM2_ALLOC_FAILED;
	}

	for (ct = 1; ct <= counts + 1; ct++) {
		memset(buf_z_ct, 0, tmp_len);
		memcpy(buf_z_ct, buf, buf_len);
		int_to_byte_8(buf_z_ct, buf_len, ct);
		if (ct <= counts) {
			wbcrypto_sm3(buf_z_ct, tmp_len, out + (ct - 1) * SM3_DIGEST_LENGTH);
		}
		else {
			memset(temp_out, 0, SM3_DIGEST_LENGTH);
			wbcrypto_sm3(buf_z_ct, tmp_len, temp_out);
			memcpy(out + (ct - 1) * SM3_DIGEST_LENGTH, temp_out, mod);
		}

	}
	free(buf_z_ct);
	free(temp_out);
	return 0;
}

/*given point(x,y), write x || y*/
int write_point_x_y(mbedtls_ecp_group* group, mbedtls_ecp_point* point, unsigned char* byte, size_t* blen) {
	size_t tmp_len = mbedtls_mpi_size(&group->P);
	return write_x_y(tmp_len, &point->X, &point->Y, byte, blen);
}

//write x || y, each with length int_length
int write_x_y(size_t int_length, mbedtls_mpi* X, mbedtls_mpi* Y, unsigned char* byte, size_t* blen) {
	int ret;
	/*byte =  x2 || y2*/
	memset(byte, 0, *blen);
	// temp += x2
	MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(X, byte, int_length));
	// temp += y2
	MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(Y, byte + int_length, int_length));
cleanup:
	*blen = int_length * 2;
	return (ret);
}

//given point(x2,y2) and m, write x2 || m || y2
int write_x2_m_y2(
	mbedtls_ecp_group* group,
	mbedtls_ecp_point* point, 
	const unsigned char* m, size_t mlen, 
	unsigned char* out, size_t* olen
) {
	int ret;
	memset(out, 0, *olen);
	size_t p_len = mbedtls_mpi_size(&(group->P));
	// out += x2
	MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&point->X, out, p_len));
	// out += m
	memcpy(out + p_len, m, mlen);
	// out += y2
	MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&point->Y, out + p_len + mlen, p_len));
cleanup: 
	*olen = p_len * 2 + mlen;
	return (ret);
}
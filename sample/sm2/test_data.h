#ifndef WBCRYPTO_SM2_TEST_DATA_H_
#define WBCRYPTO_SM2_TEST_DATA_H_

#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"

int read_group_from_hex(mbedtls_ecp_group* grp, const char* p, const char* a,
	const char* b, const char* gx, const char* gy, const char* n) {
	int ret;
	char tmp[1024];
	size_t tmp_len;
	printf("debug\n");
	if( !mbedtls_mpi_write_string(&(grp->P), 16, tmp, 1024, &tmp_len)) {
		printf("tmp_len = %d, tmp_str = %s\n", tmp_len, tmp);
	}
	if( !mbedtls_mpi_write_string(&(grp->A), 16, tmp, 1024, &tmp_len)) {
		printf("tmp_len = %d, tmp_str = %s\n", tmp_len, tmp);
	}
	if( !mbedtls_mpi_write_string(&(grp->B), 16, tmp, 1024, &tmp_len)) {
		printf("tmp_len = %d, tmp_str = %s\n", tmp_len, tmp);
	}
	if( !mbedtls_mpi_write_string(&(grp->G.X), 16, tmp, 1024, &tmp_len)) {
		printf("tmp_len = %d, tmp_str = %s\n", tmp_len, tmp);
	}
	if( !mbedtls_mpi_write_string(&(grp->G.Y), 16, tmp, 1024, &tmp_len)) {
		printf("tmp_len = %d, tmp_str = %s\n", tmp_len, tmp);
	}
	mbedtls_ecp_group_free(grp);

	MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&(grp->P), 16, p));
	MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&(grp->A), 16, a));
	MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&(grp->B), 16, b));
	MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&(grp->G.X), 16, gx));
	MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&(grp->G.Y), 16, gy));
	MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&(grp->N), 16, n));

	static mbedtls_mpi_uint one[] = { 1 };
	grp->G.Z.s = 1;
	grp->G.Z.n = 1;
	grp->G.Z.p = one;
	grp->pbits = mbedtls_mpi_bitlen(&(grp->P));
	grp->nbits = mbedtls_mpi_bitlen(&(grp->N));
	grp->h = 1;


cleanup:
	return ret;
}


char demo_user_id[] = {
	0x41, 0x4C, 0x49, 0x43, 0x45, 0x31, 0x32, 0x33,
	0x40, 0x59, 0x41, 0x48, 0x4F, 0x4F, 0x2E, 0x43,
	0x4F, 0x4D
};

//Group Parameter
const char p[] = "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3";
const char a[] = "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498";
const char b[] = "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A";

const char xG[] = "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D";
const char yG[] = "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2";

const char N[] = "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7";

//Private Key & Public Key for signing
const char sign_dA[] = "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263";
const char sign_xA[] = "0AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A";
const char sign_yA[] = "7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857";

//Private Key & Public Key for encryption
const char encrypt_dB[] = "1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0";
const char encrypt_xB[] = "435B39CCA8F3B508C1488AFC67BE491A0F7BA07E581A0E4849A5CF70628A7E0A";
const char encrypt_yB[] = "75DDBA78F15FEECB4C7895E2C1CDF5FE01DEBB2CDBADF45399CCF77BBA076A42";

#endif
#include "mbedtlspp/ecp.h"

static constexpr int BINARY_FORMAT = MBEDTLS_ECP_PF_UNCOMPRESSED;

void mbedtls::ecp_point_read_binary(mbedtls_ecp_point* point, array_view<uint8_t>& buffer, const mbedtls_ecp_group* grp) {
	mbedtls::ecp_ret_check(mbedtls_ecp_point_read_binary(grp, point, buffer.data(), buffer.size()));
}

// WARNING: THIS IS COPULED TO INTERNAL IMPLEMENTATION OF MBEDTLS //
size_t mbedtls::ecp_point_write_binary_size(const mbedtls_ecp_point* P, const mbedtls_ecp_group* grp) {
	int format = BINARY_FORMAT;
	size_t plen = mbedtls_mpi_size(&grp->P);

	if (mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_MONTGOMERY) {
		return plen;
	}

	if (mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
		/*
			* Common case: P == 0
			*/
		if (mbedtls_mpi_cmp_int(&(P->Z), 0) == 0) {
			return 1;
		}

		if (format == MBEDTLS_ECP_PF_UNCOMPRESSED) {
			return 2 * plen + 1;
		}
		else if (format == MBEDTLS_ECP_PF_COMPRESSED) {
			return plen + 1;
		}
	}

	throw mbedtls::mbedtls_exception(MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE);
}

void mbedtls::ecp_point_write_binary(const mbedtls_ecp_point* point, buffer_view<uint8_t>& buffer, const mbedtls_ecp_group* grp) {
	size_t used = 0;
	mbedtls::ecp_ret_check(
		mbedtls_ecp_point_write_binary(
			grp, point, 
			MBEDTLS_ECP_PF_UNCOMPRESSED, 
			&used, buffer.writable_data(), buffer.writable_size() 
		)
	);
	buffer.advance(used);
}
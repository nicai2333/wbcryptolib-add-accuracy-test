#ifndef MBEDTLSPP_ECP_H_
#define MBEDTLSPP_ECP_H_

#include<mbedtls/ecp.h>
#include "raii_template.h"
#include "bignum.h"
#include "memory_view/buffer_view.h"

namespace mbedtls {

	MBEDTLSPP_DEFINE_TRIVIAL_EXCEPTION_SUBTYPE(ecp_exception)
	MBEDTLSPP_DEFINE_TRIVIAL_RET_CHECK(ecp_ret_check, ecp_exception)


	inline void ecp_point_from_coordinates(mbedtls_ecp_point* p, mpi x, mpi y, mpi z) {
		x.move_into(p->X);
		y.move_into(p->Y);
		z.move_into(p->Z);
	}

	inline void ecp_point_from_coordinates(mbedtls_ecp_point* p, mpi x, mpi y) {
		return ecp_point_from_coordinates(p, std::move(x), std::move(y), mpi::read_value(1));
	}
	

	//we need to know which group this element is in to decide on the format
	void ecp_point_read_binary(mbedtls_ecp_point* point, array_view<uint8_t>& buffer, const mbedtls_ecp_group* grp);

	size_t ecp_point_write_binary_size(const mbedtls_ecp_point* point, const mbedtls_ecp_group* grp);
	void ecp_point_write_binary(const mbedtls_ecp_point* point, buffer_view<uint8_t>& buffer, const mbedtls_ecp_group* grp);


	MBEDTLSPP_DEFINE_RAII_METADATA(
		ecp_point, mbedtls_ecp_point,
		mbedtls_ecp_point_init, mbedtls_ecp_point_free
	)
	struct ecp_point : public uncopyable_raii_template<ecp_point_metadata> {

		static ecp_point from_coordinates(mpi x, mpi y, mpi z) {
			ecp_point p;
			ecp_point_from_coordinates(p.ptr(), std::move(x), std::move(y), std::move(z));
			return p;
		}

		static ecp_point from_coordinates(mpi x, mpi y) {
			ecp_point p;
			ecp_point_from_coordinates(p.ptr(), std::move(x), std::move(y));
			return p;
		}


		static ecp_point read_binary(array_view<uint8_t>& buffer, const mbedtls_ecp_group* grp) {
			ecp_point p;
			ecp_point_read_binary(p.ptr(), buffer, grp);
			return p;
		}

		size_t write_binary_size(const mbedtls_ecp_group* grp) {
			return ecp_point_write_binary_size(ptr(), grp);
		}

		void write_binary(buffer_view<uint8_t>& buffer, const mbedtls_ecp_group* grp) {
			return ecp_point_write_binary(ptr(), buffer, grp);
		}

	};

}

#endif
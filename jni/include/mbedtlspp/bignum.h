#ifndef MBEDTLSPP_BIGNUM_H_
#define MBEDTLSPP_BIGNUM_H_

#include <mbedtls/bignum.h>
#include "memory_view/array_view.h"
#include "exception.h"
#include "raii_template.h"

namespace mbedtls {

	MBEDTLSPP_DEFINE_TRIVIAL_EXCEPTION_SUBTYPE(mpi_exception)
	MBEDTLSPP_DEFINE_TRIVIAL_RET_CHECK(mpi_ret_check, mpi_exception)


	inline void mpi_read_binary(mbedtls_mpi* value, const array_view<uint8_t>& arr) {
		mpi_ret_check(mbedtls_mpi_read_binary(value, arr.data(), arr.size()));
	}

	inline void mpi_read_value(mbedtls_mpi* value, mbedtls_mpi_sint i) {
		mpi_ret_check(mbedtls_mpi_lset(value, i));
	}


	MBEDTLSPP_DEFINE_COPYABLE_RAII_METADATA(
		mpi, mbedtls_mpi,
		mbedtls_mpi_init, mbedtls_mpi_copy, mbedtls_mpi_free
	)
	struct mpi : public uncopyable_raii_template<mpi_metadata> {
	
		static mpi read_binary(const array_view<uint8_t>& arr) {
			mpi value;
			mpi_read_binary(value.ptr(), arr);
			return value;
		}

		static mpi read_value(mbedtls_mpi_sint i) {
			mpi value;
			mpi_read_value(value.ptr(), i);
			return value;
		}
	
	};

};

#endif
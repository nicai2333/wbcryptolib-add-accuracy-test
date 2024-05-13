#ifndef MBEDTLSPP_CTR_DRBG_H_
#define MBEDTLSPP_CTR_DRBG_H_

#include <mbedtls/ctr_drbg.h>
#include "memory_view/array_view.h"
#include "mbedtlspp/entropy.h"
#include "exception.h"
#include "raii_template.h"

namespace mbedtls {

	MBEDTLSPP_DEFINE_TRIVIAL_EXCEPTION_SUBTYPE(drbg_exception)
	MBEDTLSPP_DEFINE_TRIVIAL_RET_CHECK(drbg_ret_check, drbg_exception)


	//use the entropy context to initialize the drbg_context
	//note: due to a pointer retention, the drbg context must live shorter than entropy context!
	//note: pass in seed with default constructed array_view({NULL, 0}) to indicate no seed provided
	inline void ctr_drbg_with_entropy_source(
		mbedtls_ctr_drbg_context* ctx, 
		entropy_context& entropy, 
		const array_view<uint8_t>& seed = array_view<uint8_t>{}
	) {
		drbg_ret_check(mbedtls_ctr_drbg_seed(
			ctx, mbedtls_entropy_func, entropy.ptr(),
			seed.data(), seed.size()
		));
	}


	MBEDTLSPP_DEFINE_RAII_METADATA(
		ctr_drbg_context,mbedtls_ctr_drbg_context, 
		mbedtls_ctr_drbg_init, mbedtls_ctr_drbg_free
	)
	struct ctr_drbg_context : public uncopyable_raii_template<ctr_drbg_context_metadata> {

		static ctr_drbg_context with_entropy_source(
			entropy_context& entropy, 
			const array_view<uint8_t>& seed = array_view<uint8_t>{}
		) {
			ctr_drbg_context ctr_drbg;
			ctr_drbg_with_entropy_source(ctr_drbg.ptr(), entropy, seed);
			return ctr_drbg;
		}

	};

};

#endif
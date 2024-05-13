#ifndef MBEDTLSPP_ENTROPY_H_
#define MBEDTLSPP_ENTROPY_H_

#include <mbedtls/entropy.h>
#include <mbedtls/entropy_poll.h>
#include "exception.h"
#include "raii_template.h"

namespace mbedtls {

	MBEDTLSPP_DEFINE_TRIVIAL_EXCEPTION_SUBTYPE(entropy_exception)
	MBEDTLSPP_DEFINE_TRIVIAL_RET_CHECK(entropy_ret_check, entropy_exception)


	inline void entropy_with_platform_entropy_source(mbedtls_entropy_context* ctx) {
		entropy_ret_check(mbedtls_entropy_add_source(
			ctx,
			mbedtls_platform_entropy_poll, NULL,
			MBEDTLS_ENTROPY_MIN_PLATFORM, MBEDTLS_ENTROPY_SOURCE_STRONG
		));
	}


	MBEDTLSPP_DEFINE_RAII_METADATA(
		entropy_context, mbedtls_entropy_context,
		mbedtls_entropy_init, mbedtls_entropy_free
	)
	struct entropy_context : public uncopyable_raii_template<entropy_context_metadata> {
	
		static entropy_context with_platform_entropy_source(){
			entropy_context ctx;
			entropy_with_platform_entropy_source(ctx.ptr());
			return ctx;
		}

	};

}

#endif